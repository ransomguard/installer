import sys,unittest,socket,json
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from readiness import blockers
from jev_network import configure
from release_policy import check_channel

class ReadinessTests(unittest.TestCase):
    def good(self):
        return dict(elevated=True,architecture='x64',build=19045,vss_disabled=False,
                    altitude_scan_complete=True,altitude_conflicts=[],system_filesystem='NTFS',
                    system_disk_free_bytes=20*1024**3,test_signing=True,secure_boot=False)
    def test_default_os_rejected_for_lab_but_not_ms_signed_channel(self):
        i=self.good();i.update(test_signing=False,secure_boot=True)
        self.assertTrue(blockers(i,'isolated-lab'))
        self.assertEqual(blockers(i,'internal-preview'),[])
    def test_arm64_is_not_x64(self):
        i=self.good();i['architecture']='ARM64'
        self.assertTrue(blockers(i,'internal-preview'))
    def test_unified_test_channel_accepts_vm_and_host_but_keeps_security_gates(self):
        request={'internal_test':True,'acknowledge_pc_wide_containment':True}
        for model in ('VMware Virtual Platform','Physical PC'):
            info={'computer':{'model':model},'readiness':self.good()}
            self.assertEqual(check_channel({'channel':'internal-test'},info,request,'.',None)['channel'],'internal-test')
            for field,value in (('secure_boot',True),('test_signing',False),('architecture','ARM64')):
                bad={'computer':info['computer'],'readiness':dict(self.good(),**{field:value})}
                with self.assertRaises(ValueError):check_channel({'channel':'internal-test'},bad,request,'.',None)
    def test_test_pc_needs_existing_boot_policy_and_explicit_acknowledgement(self):
        info={'computer':{'model':'Physical PC'},'readiness':self.good()}
        request={'internal_test':True,'acknowledge_pc_wide_containment':True}
        self.assertTrue(check_channel({'channel':'internal-test'},info,request,'.',None)['windows_signature_enforcement'])
        with self.assertRaises(ValueError):check_channel({'channel':'internal-test'},info,{},'.',None)
        info['readiness']['test_signing']=False
        with self.assertRaises(ValueError):check_channel({'channel':'internal-test'},info,request,'.',None)
    def test_unknown_security_and_altitude_collision_fail_closed(self):
        for changes in ({'secure_boot':None},{'test_signing':None},{'altitude_scan_complete':False},{'altitude_conflicts':['other_filter']}):
            i=self.good();i.update(changes)
            self.assertTrue(blockers(i,'isolated-lab'))
    def test_disconnected_install_never_resolves_or_allows_unvalidated_address(self):
        calls=[]
        def ps(code,data,**kwargs):calls.append(data);return json.dumps({'configured':True,'verified':True,'addresses':data['addresses']})
        with patch('jev_network.socket.getaddrinfo') as resolve:
            self.assertEqual(configure('bridge','backup',ps,resolve_endpoint=False)['addresses'],[])
            resolve.assert_not_called()
        with patch('jev_network.socket.getaddrinfo',side_effect=socket.gaierror):
            self.assertEqual(configure('bridge','backup',ps)['addresses'],[])
        with patch('jev_network.socket.getaddrinfo',return_value=[(socket.AF_INET,0,0,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):configure('bridge','backup',ps)
        self.assertEqual(len(calls),2)
    def test_unverified_or_failed_firewall_setup_never_reports_success(self):
        for output in ({'configured':True},{'configured':False,'verified':True}):
            with self.assertRaises(ValueError):
                configure('bridge','backup',lambda *a,**kw:json.dumps(output),resolve_endpoint=False)
        def failed(*a,**kw):raise TimeoutError('provider timeout')
        with self.assertRaises(TimeoutError):configure('bridge','backup',failed,resolve_endpoint=False)
