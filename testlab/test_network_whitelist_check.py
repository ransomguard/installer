import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec=importlib.util.spec_from_file_location('probe',Path(__file__).with_name('network-whitelist-check.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def row(phase,active,allow=True,deny=True):
    return {'phase':phase,'before':{'active':active,'whitelist':[]},'after':{'active':active,'whitelist':[]},'target_roles_verified':True,
            'probes':[{'https':allow},{'https':not active,'tcp':not deny if active else True,'winerror':10013 if active and deny else None}]}
class VerdictTests(unittest.TestCase):
    def setUp(self):self.rows=[row('before',False),row('during',True),row('after',False)]
    def test_complete_pass(self):self.assertEqual(module.evaluate(self.rows)[0],'PASS')
    def test_unlisted_connect_is_failure(self):
        self.rows[1]['probes'][1]['tcp']=True
        self.assertEqual(module.evaluate(self.rows)[0],'FAIL')
    def test_missed_window_is_not_pass(self):
        self.rows[1]['after']['active']=False
        self.assertEqual(module.evaluate(self.rows)[0],'INCONCLUSIVE')
    def test_timeout_alone_is_not_pass(self):
        self.rows[1]['probes'][1]['winerror']=None
        self.assertEqual(module.evaluate(self.rows)[0],'INCONCLUSIVE')
    def test_no_recovery_connectivity_is_not_pass(self):
        self.rows[-1]['probes'][0]['https']=False
        self.assertEqual(module.evaluate(self.rows)[0],'INCONCLUSIVE')
    def test_overlap_or_unknown_rules_is_not_pass(self):
        self.rows[1]['target_roles_verified']=False
        self.assertEqual(module.evaluate(self.rows)[0],'INCONCLUSIVE')
    def test_allowed_denied_is_failure(self):
        self.rows[1]['probes'][0]={'https':False,'winerror':10013}
        self.assertEqual(module.evaluate(self.rows)[0],'FAIL')
    def test_policy_change_is_not_pass(self):
        self.rows[1]['after']['whitelist']=[1]
        self.assertEqual(module.evaluate(self.rows)[0],'INCONCLUSIVE')
    def test_native_fallback_retains_tls_checks_and_requires_success(self):
        with patch.dict(module.os.environ,{'SystemRoot':'C:/Windows'}), patch.object(module.subprocess,'run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout='200 1.2.3.4',stderr='')
            self.assertTrue(module.native_https('example.com','1.2.3.4')['https'])
            args=run.call_args.args[0]
            self.assertNotIn('--insecure',args);self.assertNotIn('-k',args)
            self.assertIn('example.com:443:1.2.3.4',args)
            run.return_value=SimpleNamespace(returncode=60,stdout='000 1.2.3.4',stderr='certificate failed')
            self.assertFalse(module.native_https('example.com','1.2.3.4')['https'])
if __name__=='__main__':unittest.main()
