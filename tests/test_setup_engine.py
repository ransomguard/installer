import importlib.util,json,tempfile,unittest,hashlib
from unittest.mock import patch
from pathlib import Path
P=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',P/'src/setup_engine.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class InstallerTests(unittest.TestCase):
    def test_build_version_is_derived_from_engine(self):
        import ast
        tree=ast.parse((P/('build.py' if (P/'build.py').exists() else 'build-reference.py')).read_text(encoding='utf-8-sig'))
        node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='version' for t in n.targets))
        namespace={'ast':ast,'B':P}
        actual=eval(compile(ast.Expression(node.value),'<build-version>','eval'),namespace)
        self.assertEqual(actual,m.VERSION)
        changed=P/'src/setup_engine.py'
        original=changed.read_text(encoding='utf-8-sig')
        with patch.object(Path,'read_text',return_value=original.replace(m.VERSION,'9.9.9-test')):
            self.assertEqual(eval(compile(ast.Expression(node.value),'<build-version>','eval'),namespace),'9.9.9-test')
    def test_background_tasks_use_windowless_python(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t);python=base/'python.exe';windowless=base/'pythonw.exe'
            windowless.write_bytes(b'fixture')
            with patch.object(m,'ps') as ps,patch('ransomguard.snapshot_settings.interval_minutes',return_value=60),patch('ransomguard.snapshots.default_state_db',return_value=base/'snapshots.db'):
                m.register_tasks(base,{'python':str(python)},base/'backup')
                code,data=ps.call_args.args
                self.assertEqual(data['python'],str(windowless))
                self.assertIn('New-ScheduledTaskAction -Execute $i.python',code)
                windowless.unlink()
                with self.assertRaisesRegex(RuntimeError,'Background Python'):m.register_tasks(base,{'python':str(python)},base/'backup')
    def test_install_never_changes_network_even_with_legacy_isolation_request(self):
        from unittest.mock import Mock
        runner=Mock(side_effect=AssertionError('Installer must not invoke network commands'))
        with patch('jev_network.configure',side_effect=AssertionError('Installer must not configure isolation')) as configure:
            for channel in ('isolated-lab','internal-test','internal-preview'):
                for old in (None,{'installed':True}):
                    for request in ({},{'jev_only_network':True},{'jev_only_network':False}):
                        result=m.prepare_network(channel,old,request,'bridge','backup',runner)
                        self.assertTrue(result['preserved_existing'])
                        self.assertFalse(result['configured'])
                        self.assertEqual(result['mode'],'incident_response_only')
            runner.assert_not_called();configure.assert_not_called()
    def test_missing_key_still_provisions_dashboard_transport(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t);installroot=base/'installed'
            def write(path,value):path.write_text(json.dumps(value),encoding='utf-8')
            with patch.object(m,'save',side_effect=write):
                result=m.ensure_jev_transport(base,installroot)
                self.assertEqual(result['endpoint'],'https://api.typesafe.ai')
                self.assertEqual(Path(result['bridge']),installroot/'bridge/RansomGuard.JevBridge.exe')
                self.assertNotIn('api_key',result)
                self.assertEqual(m.ensure_jev_transport(base,base/'different'),result)
    def test_legacy_paths_parse_without_execution(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);(b/'Start-RansomGuard.py').write_text("raise AssertionError('must not execute')\nROOT=Path('C:/root')\nPY=ROOT/'python.exe'\nUI=Path('C:/ui/app.exe')\nDAEMON=Path('C:/firewall/fw.exe')\n")
            v=m.legacy_paths(b);self.assertEqual(Path(v['python']),Path('C:/root/python.exe'))
    def test_payload_tamper_and_escape_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);(b/'app').write_bytes(b'valid')
            manifest={'schema':1,'files':{'app':hashlib.sha256(b'valid').hexdigest()}}
            (b/'payload-manifest.json').write_text(json.dumps(manifest));m.verify_payload(b)
            (b/'app').write_bytes(b'bad')
            with self.assertRaises(ValueError):m.verify_payload(b)
            manifest['files']={'../outside':'bad'};(b/'payload-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):m.verify_payload(b)
