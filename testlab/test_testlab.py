import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import testlab as t

class SafetyAndEvidence(unittest.TestCase):
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
