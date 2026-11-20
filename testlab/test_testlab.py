import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import testlab as t

class SafetyAndEvidence(unittest.TestCase):
    def test_health_retries_transient_atomic_replace_sharing_error(self):
        ready={'worker_state':'running','observed_at':10,'counter_totals':{},'driver_status':{},'pending_intake':0}
        with patch.object(t,'load',side_effect=[PermissionError('busy'),ready]),patch.object(t.time,'time',return_value=10),patch.object(t.time,'sleep'):
            self.assertEqual(t.health(Path('unused')),ready)

    def test_response_requires_effective_worker_authorization_and_exact_scope(self):
        import sys, types
        module=types.ModuleType('ransomguard.live_profile')
        module.observer_options=lambda *a,**k: (['--live-track-a','--response-path-prefix','scope'], 'unused')
        good={'response_authorized':True,'response_tracks':['A'],'response_path_prefix':'scope','response_collection_invalid':False}
        with patch.dict(sys.modules,{'ransomguard.live_profile':module}):
            for h in ({},dict(good,response_authorized=False),dict(good,response_path_prefix='other'),dict(good,response_tracks=['B']),dict(good,response_collection_invalid=True)):
                with self.subTest(h=h),patch.object(t,'health',return_value=h):
                    with self.assertRaises(RuntimeError):t.require_live_worker(Path('unused'),'A')
            with patch.object(t,'health',return_value=good):
                self.assertEqual(t.require_live_worker(Path('unused'),'A'),good)

    def test_settled_waits_for_post_workload_statistics(self):
        old={'observed_at':99,'pending_intake':0,'driver_status':{'queue_depth':0}}
        new=dict(old,observed_at=100)
        with patch.object(t,'health',side_effect=[old,new]),patch.object(t.time,'time',return_value=100),patch.object(t.time,'monotonic',return_value=0),patch.object(t.time,'sleep'):
            self.assertIs(t.settled(Path('unused')),new)

    def test_stale_empty_queue_is_not_a_success_at_deadline(self):
        old={'observed_at':99,'pending_intake':0,'driver_status':{'queue_depth':0}}
        with patch.object(t,'health',return_value=old),patch.object(t.time,'time',return_value=100),patch.object(t.time,'monotonic',side_effect=[0,121]),patch.object(t.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'measurement barrier'):t.settled(Path('unused'))

    def test_waits_for_real_statistics_after_scope_handover(self):
        first={'worker_state':'running','observed_at':10}
        ready=dict(first,counter_totals={'events_dropped':7},driver_status={},pending_intake=0)
        with patch.object(t,'load',side_effect=[first,ready]), patch.object(t.time,'time',return_value=10), patch.object(t.time,'sleep') as sleep:
            result=t.health(Path('unused'))
        self.assertEqual(result['counter_totals']['events_dropped'],7)
        sleep.assert_called_once_with(.5)

    def test_refuses_unknown_existing_folder(self):
        with tempfile.TemporaryDirectory() as d, patch.object(t,'HOME',Path(d)), patch.object(t,'SCOPE',Path(d)/'Protected'):
            t.SCOPE.mkdir(); (t.SCOPE/'important.txt').write_text('keep')
            with self.assertRaises(RuntimeError): t.prepare()
            self.assertEqual((t.SCOPE/'important.txt').read_text(),'keep')

    def test_prepare_does_not_overwrite_modified_evidence(self):
        with tempfile.TemporaryDirectory() as d, patch.object(t,'HOME',Path(d)), patch.object(t,'SCOPE',Path(d)/'Protected'):
            t.prepare(); p=t.SCOPE/t.NAMES[0]; p.write_text('changed')
            t.prepare(); self.assertEqual(p.read_text(),'changed')

    def test_unexpected_files_rejected(self):
        with tempfile.TemporaryDirectory() as d, patch.object(t,'HOME',Path(d)), patch.object(t,'SCOPE',Path(d)/'Protected'):
            t.prepare(); (t.SCOPE/'unknown').write_text('keep')
            with self.assertRaises(RuntimeError): t.prepare()

    def test_counter_reset_and_restart_not_success(self):
        h={'pid':1,'counter_totals':dict(events_generated=10,events_delivered=5,events_dropped=5,events_flushed=0)}
        reset={'pid':1,'counter_totals':dict(events_generated=1,events_delivered=1,events_dropped=0,events_flushed=0)}
        with self.assertRaises(RuntimeError): t.delta(h,reset)
        with self.assertRaises(RuntimeError): t.delta(h,dict(h,pid=2))
        self.assertEqual(t.delta(h,h)['events_dropped'],0)

    def test_workload_bounded_to_run(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); sentinel=root/'untouched'; sentinel.write_text('keep')
            run=root/'run';run.mkdir();t.workload('burst',run,10);t.workload('mixed',run,70)
            self.assertEqual(sentinel.read_text(),'keep')
            self.assertEqual(len(list(run.glob('normal-*.txt'))),64)
            self.assertEqual((run/'writes.txt').read_text().count('\n'),10)

if __name__=='__main__': unittest.main()
