import json,sqlite3,sys,tempfile,unittest
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from lifecycle import plan
from release_policy import check_channel

@contextmanager
def database(path):
    db=sqlite3.connect(path)
    try:
        with db:yield db
    finally:db.close()

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.app=self.base/'App';(self.app/'v1').mkdir(parents=True)
        self.runtime=self.base/'Runtime';self.runtime.mkdir()
        with database(self.runtime/'observe.sqlite3') as db:
            db.execute('CREATE TABLE response_jobs(state TEXT)');db.execute('CREATE TABLE live_response_attempts(state TEXT)')
        with database(self.runtime/'holds.sqlite3') as db:db.execute('CREATE TABLE firewall_holds(state TEXT)')
        self.receipt={'state':'running','runtime':str(self.runtime),'version':'v1','owns_deployment':True}
    def test_idle_owned_deployment_can_be_removed_without_db_changes(self):
        before=(self.runtime/'observe.sqlite3').read_bytes()
        self.assertTrue(plan(self.receipt,self.app)['allowed'])
        self.assertEqual(before,(self.runtime/'observe.sqlite3').read_bytes())
    def test_each_unresolved_state_blocks_removal(self):
        for file,table,state in [('observe.sqlite3','response_jobs','READY'),('observe.sqlite3','response_jobs','RUNNING'),('observe.sqlite3','live_response_attempts','RESERVED'),('observe.sqlite3','live_response_attempts','REVIEW_REQUIRED'),('holds.sqlite3','firewall_holds','acknowledged')]:
            with self.subTest(state=state):
                with database(self.runtime/file) as db:db.execute('INSERT INTO '+table+' VALUES(?)',(state,))
                self.assertFalse(plan(self.receipt,self.app)['allowed'])
                with database(self.runtime/file) as db:db.execute('DELETE FROM '+table)
    def test_missing_database_fails_closed(self):
        (self.runtime/'holds.sqlite3').unlink()
        self.assertFalse(plan(self.receipt,self.app)['allowed'])
        self.assertFalse((self.runtime/'holds.sqlite3').exists())
    def test_path_escape_and_migrated_ownership_block(self):
        self.receipt['version']='../Runtime';self.assertFalse(plan(self.receipt,self.app)['allowed'])
        self.receipt.update(version='v1',old_paths={'python':'legacy'},owns_deployment=False)
        self.assertFalse(plan(self.receipt,self.app)['allowed'])
    def test_lab_cannot_install_on_physical_pc(self):
        with self.assertRaises(ValueError):check_channel({'channel':'isolated-lab'},{'computer':{'model':'ThinkPad'}},{'isolated_lab':True},self.base,None)
    def test_manifest_claim_does_not_bypass_missing_microsoft_signature(self):
        with self.assertRaises(ValueError):check_channel({'channel':'internal-preview','microsoft_signed':True},{},{'internal_test':True},self.base,None)
    def test_untrusted_and_non_microsoft_signatures_rejected(self):
        paths=[]
        for name in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter'):
            d=self.base/'drivers'/name;d.mkdir(parents=True)
            for ext in ('.sys','.cat','.inf'):(d/(name+ext)).write_bytes(b'test')
            paths.extend([str(d/(name+'.sys')),str(d/(name+'.cat'))])
        for status,subject in [('Valid','CN=RansomGuard Test'),('NotTrusted','CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation')]:
            fake=lambda *a:json.dumps([dict(path=p,status=status,subject=subject) for p in paths])
            with self.assertRaises(ValueError):check_channel({'channel':'internal-preview'},{},{'internal_test':True},self.base,fake)

if __name__=='__main__':unittest.main()
