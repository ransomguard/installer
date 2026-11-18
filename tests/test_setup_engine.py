import importlib.util,json,tempfile,unittest,hashlib
from pathlib import Path
P=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',P/'src/setup_engine.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class InstallerTests(unittest.TestCase):
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
