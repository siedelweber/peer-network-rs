"""Negative admission fixtures for syntax coverage and semantic review bindings."""
import copy
import io
import json
import unittest

from devperf import StructuralError
from observe import identity, validate


def fixture():
    function=dict(package='fixture',path='packages/fixture/src/lib.rs',item='run',owner='ROOT',
                  public=True,const=False,signature='fn run ()',body='{ work () ; }',attributes=[],
                  boundary=dict(helper='tracing::instrument',name='rule:observe:spans',execution_owner='ROOT',claim_owner='ROOT',claim_label='rule:observe:spans',source_item='run',records_result=True))
    operation={key:function[key] for key in ('package','path','item','owner','signature')}
    operation.update(claim='ROOT::rule:observe:spans',mode='instrumented',fields=['arguments','result'],metrics=['fixture__elapsed_seconds'])
    name=identity(function)
    assessment=dict(status='reviewer-confirmed',premises='The fixture has no credential field and returns unit.',negative_probe='ROOT::claim:discipline:semantic-review-is-bound-to-source')
    review=dict(operation=name,body=function['body'],full_recording=assessment,secret_flow=assessment,exposure_consumers=assessment,class_decision='fixture',item_premise='The body returns unit with no credential or public payload.')
    data=dict(schema=1,functions=[function],generators=[])
    register=dict(schema=1,named_operations=[],operations=[operation],generators=[],reviews=[review],class_decisions=[dict(name='fixture',status='reviewer-confirmed',premises='Public unit operation.',operations=[name])],
                  metrics=[dict(name='fixture__elapsed_seconds',unit='seconds',kind='histogram',attributes={})])
    return data,register,{'ROOT::rule:observe:spans'},{assessment['negative_probe']}


class Admission(unittest.TestCase):
    def test_resource_samples(self):
        """Claim: Cgroup counters, PSI percentages and memory readings retain their units and start/end deltas, while an absent file or migrated cgroup makes its delta unavailable rather than zero.
        ´claim:discipline:cgroup-deltas-preserve-unavailable-readings´
        ´test:integration:test-resource-samples´
        """
        import tempfile
        from pathlib import Path
        from gate_resources import sample, report
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'cpu.stat').write_text('usage_usec 10\nuser_usec 6\nsystem_usec 4\nnr_throttled 0\n')
            (root/'cpu.pressure').write_text('some avg10=1.0 avg60=2.0 avg300=3.0 total=100\n')
            (root/'memory.current').write_text('50\n')
            start=sample(root)
            (root/'cpu.stat').write_text('usage_usec 30\nuser_usec 16\nsystem_usec 14\nnr_throttled 2\n')
            (root/'memory.current').write_text('40\n')
            end=sample(root)
            delta=report(start,end)['deltas']
            self.assertEqual(delta['cpu.stat.usage_usec'],20)
            self.assertEqual(delta['cpu.stat.nr_throttled'],2)
            self.assertEqual(delta['memory.current'],-10)
            self.assertIsNone(delta['memory.peak'])
            self.assertIsNone(delta['io.pressure.some.total'])
            self.assertEqual(start['values']['cpu.pressure.some.avg10'],1.0)
            end['cgroup']='another'
            self.assertTrue(all(v is None for v in report(start,end)['deltas'].values()))

    def test_process_delivery_counts(self):
        """Claim: Inline warning and error counts remain distinct from verdicts, and each process retains its delivered and lost counts without treating missing delivery evidence as a measured zero.
        ´claim:discipline:process-delivery-counts-remain-independent´
        ´test:integration:test-process-delivery-counts´
        """
        from gate_observation_counts import counts
        result=counts([b'{"level":"WARN"}',b'{"level":"ERROR"}',b'{"kind":"observation_status","process_id":7,"delivered_records":4,"lost_records":2}',b'not json'])
        self.assertEqual((result['warn'],result['error'],result['loss']),(1,1,2))
        self.assertEqual(result['processes'][0]['delivered'],5)
        self.assertEqual(counts([b'{"kind":"observation_status"}'])['processes'][0]['delivered'],None)

    def test_observation_streams(self):
        """Claim: Gate routing preserves complete observation bytes in the artifact and leaves diagnostics and malformed lines byte-identical in the main log, without treating an observation level as a verdict.
        ´claim:discipline:observation-stream-routing-is-lossless´
        ´test:integration:test-observation-streams´
        """
        from observation_log import separate
        observation = b'{"kind":"trace","level":"ERROR","fields":{"public":"whole"}}\n'
        diagnostic = b'{"kind":"runtime_error","message":"public"}\n'
        malformed = b'not json\xff\n'
        output, artifact = io.BytesIO(), io.BytesIO()
        self.assertEqual(separate(io.BytesIO(observation + diagnostic + malformed), artifact, output), 1)
        self.assertEqual(artifact.getvalue(), observation)
        self.assertEqual(output.getvalue(), diagnostic + malformed)
        for kind in ('span_envelope','metering','metric_summary','export_summary','observation_artifact','observation_status'):
            record=json.dumps({'kind':kind,'public':'complete'}).encode()+b'\n'
            output,artifact=io.BytesIO(),io.BytesIO()
            self.assertEqual(separate(io.BytesIO(record),artifact,output),1)
            self.assertEqual(artifact.getvalue(),record)
            self.assertEqual(output.getvalue(),b'')

    def test_omitted_instrumentation(self):
        """Claim: A registered public function whose parsed body has no reviewed boundary refuses, even when its declaration and semantic review remain present.
        ´claim:discipline:public-bodies-require-parsed-boundaries´
        ´test:integration:test-omitted-instrumentation´
        """
        args=fixture()
        self.assertEqual(validate(*args)['instrumented'],1)
        args[0]['functions'][0]['boundary']=None
        with self.assertRaisesRegex(StructuralError,'omitted instrumentation'):validate(*args)

    def test_wrong_identity(self):
        """Claim: A boundary cannot claim another owner or an unresolved or different label while retaining a valid source item and review.
        ´claim:discipline:operation-identity-matches-its-source´
        ´test:integration:test-wrong-identity´
        """
        for field,value in [('owner','FOREIGN'),('claim','ROOT::rule:missing:label')]:
            args=fixture();args[1]['operations'][0][field]=value
            with self.assertRaises(StructuralError):validate(*args)
        args=fixture();args[0]['functions'][0]['boundary']['execution_owner']='FOREIGN'
        with self.assertRaisesRegex(StructuralError,'wrong instrumentation'):validate(*args)
        args=fixture();args[0]['functions'][0]['boundary']['name']='rule:wrong:label'
        with self.assertRaisesRegex(StructuralError,'primary span label'):validate(*args)

    def test_stale_operation(self):
        """Claim: Deleting a public function or changing its signature leaves a structural stale mapping; duplicating its registry row cannot conceal the mismatch.
        ´claim:discipline:operation-roster-cannot-retain-stale-items´
        ´test:integration:test-stale-operation´
        """
        args=fixture();args[0]['functions']=[]
        with self.assertRaisesRegex(StructuralError,'stale operation'):validate(*args)
        args=fixture();args[0]['functions'][0]['signature']='fn run (x: u8)'
        with self.assertRaisesRegex(StructuralError,'stale source'):validate(*args)
        args=fixture();args[1]['operations'].append(copy.deepcopy(args[1]['operations'][0]))
        with self.assertRaisesRegex(StructuralError,'duplicate operation'):validate(*args)

    def test_duplicate_metric(self):
        """Claim: Two declarations of one metric name refuse even when their units agree, preventing ambiguous ownership of a runtime series.
        ´claim:discipline:metric-names-have-one-declaration´
        ´test:integration:test-duplicate-metric´
        """
        args=fixture();args[1]['metrics'].append(copy.deepcopy(args[1]['metrics'][0]))
        with self.assertRaisesRegex(StructuralError,'duplicate metric'):validate(*args)

    def test_undeclared_dimension(self):
        """Claim: A metric with an undeclared time unit or an unbounded request attribute refuses before it can be represented as a declared bounded series.
        ´claim:discipline:metric-units-and-attributes-are-declared´
        ´test:integration:test-undeclared-dimension´
        """
        for field,value in [('unit','ticks'),('attributes',{'request':['arbitrary']})]:
            args=fixture();args[1]['metrics'][0][field]=value
            with self.assertRaisesRegex(StructuralError,'undeclared metric'):validate(*args)

    def test_invalid_exception(self):
        """Claim: An exception cannot waive multiple rules, omit an item-local justification or cite a missing boundary witness; a runtime body cannot claim const evaluation.
        ´claim:discipline:coverage-exceptions-are-local-and-witnessed´
        ´test:integration:test-invalid-exception´
        """
        reason='Justified: The fixture is evaluated within its declared caller.'
        base=fixture();function=base[0]['functions'][0];row=base[1]['operations'][0]
        anchor=copy.deepcopy(function);anchor['item']='outer';anchor['boundary']['source_item']='outer'
        base[0]['functions'].append(anchor)
        anchor_row=copy.deepcopy(row);anchor_row['item']='outer';base[1]['operations'].append(anchor_row)
        anchor_review=copy.deepcopy(base[1]['reviews'][0]);anchor_review['operation']=identity(anchor);base[1]['reviews'].append(anchor_review)
        function['attributes']=[reason];function['boundary']=None;row['mode']='exception'
        base[1]['class_decisions'][0]['operations'].append(identity(anchor))
        row['exception']=dict(rule='ROOT::rule:observe:spans',kind='inherited',justification=reason,witness=next(iter(base[3])),boundary=identity(anchor),class_decision='fixture',enclosing_operations=[identity(anchor)])
        self.assertEqual(validate(*base)['exceptions'],1)
        for mutation in ('rule','local','witness','const','cycle','enclosing'):
            args=copy.deepcopy(base);function=args[0]['functions'][0];row=args[1]['operations'][0]
            if mutation=='rule':row['exception']['rule']='all rules'
            elif mutation=='local':function['attributes']=[]
            elif mutation=='witness':row['exception']['witness']='ROOT::claim:missing:witness'
            elif mutation=='cycle':row['exception']['boundary']=identity(function)
            elif mutation=='enclosing':row['exception']['enclosing_operations']=[]
            else:row['exception']['kind']='const'
            with self.assertRaises(StructuralError):validate(*args)

    def test_semantic_review(self):
        """Claim: Full-recording, secret-flow and exposure assessments remain separately reviewer-confirmed and bound to the inspected body; absent negative evidence or a changed body refuses mechanical admission.
        ´claim:discipline:semantic-review-is-bound-to-source´
        ´test:integration:test-semantic-review´
        """
        args=fixture();self.assertIn('not mechanical proof',validate(*args)['semantic_status'])
        for field in ('full_recording','secret_flow','exposure_consumers'):
            args=fixture();args[1]['reviews'][0][field]={}
            with self.assertRaisesRegex(StructuralError,'reviewer-confirmed'):validate(*args)
        args=fixture();args[0]['functions'][0]['body']='{ leak (credential) ; }'
        with self.assertRaisesRegex(StructuralError,'stale semantic'):validate(*args)
        args=fixture();args[0]['types']=[{'item':'Connection','syntax':'struct Connection { password: String }'}]
        with self.assertRaisesRegex(StructuralError,'type declarations changed'):validate(*args)
        for field in ('class_decision','item_premise'):
            args=fixture();args[1]['reviews'][0].pop(field)
            with self.assertRaisesRegex(StructuralError,'body-bound semantic class'):validate(*args)

    def test_generated_mapping(self):
        """Claim: A newly generated entry point cannot disappear from the census join or be admitted by copying its syntax without an expansion review and enclosing boundaries.
        ´claim:discipline:generated-entry-points-need-explicit-admission´
        ´test:integration:test-generated-mapping´
        """
        args=fixture();generator=dict(package='fixture',path='packages/fixture/src/lib.rs',item='State',kind='derive',syntax='#[derive(Debug)]')
        args[0]['generators']=[generator]
        with self.assertRaisesRegex(StructuralError,'generator mapping'):validate(*args)
        args[1]['generators']=[copy.deepcopy(generator)]
        with self.assertRaisesRegex(StructuralError,'uninspected generated'):validate(*args)


if __name__=='__main__':unittest.main()
