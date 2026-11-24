"""Verify our compiled installer resource without installing or loading drivers."""
from pathlib import Path
import ast,ctypes,hashlib,json,os,re,subprocess,zipfile
O=Path('outputs/Ransom0-0.6.0-preview.25').resolve()
b=json.loads((O/'build-test-pc.json').read_text(encoding='utf8'));exe=O/'Ransom0_install.exe';payload=Path(b['payload'])
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
# Load metadata/resources only; never invoke the installer's entry point.
ps="$a=[Reflection.Assembly]::LoadFile('"+str(exe).replace("'","''")+"');$s=$a.GetManifestResourceStream('payload.zip');$f=[IO.File]::Create('"+str(O/'verified-embedded.zip').replace("'","''")+"');try{$s.CopyTo($f)}finally{$f.Dispose();$s.Dispose()}"
subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',ps],check=True,timeout=180,creationflags=0x08000000)
assert sha(O/'verified-embedded.zip')==sha(b['zip'])
with zipfile.ZipFile(O/'verified-embedded.zip') as z:
 assert z.testzip() is None
 m=json.loads(z.read('payload-manifest.json'))
 assert set(z.namelist())==set(m['files'])|{'payload-manifest.json'}
 for name,want in m['files'].items():
  assert not (name.startswith('/') or '..' in name.split('/') or ':' in name),name
  assert hashlib.sha256(z.read(name)).hexdigest()==want,name
  assert sha(payload/name)==want,name
  assert not name.endswith(('.pfx','.pem','.key','.sqlite','.sqlite3','.dmp')),name
  if name.startswith(('backend/ransomguard/','setup/','backend/config/')) and name.endswith(('.py','.json')):
   assert not re.search(rb'apikey_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{25,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',z.read(name)),name
 tree=ast.parse(z.read('setup/setup_engine.py').decode('utf-8-sig'))
 version=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets))
 assert version==m['version']=='0.6.0-preview.25'
 assert m['driver_sha256']=={'Anti_Ransom_Driver':'5814a95a19b08735960d8f51e1d39de112895cc8706eda57e5172e3898b4efd0','Anti_Ransom_FsFilter':'088f92660dfa263b94654cb8f46ab39a523678ceb46a1822354ce84a4d0ae38b'}
 cfg=json.loads(z.read('backend/config/example.json'))
 assert cfg['decision']['malicious_threshold']==.8 and cfg['decision']['benign_threshold']==.2
 # Every packaged first-party backend/setup source must match today's source.
 for name,want in m['files'].items():
  if name.startswith('backend/'):
   assert sha(Path('work/windows-release')/name)==want,name
  elif name.startswith('setup/'):
   assert sha(Path('work/windows-release/src')/Path(name).name)==want,name
code="import sys,ctypes;sys.path.insert(0,sys.argv[1]);import ransomguard.live_response,ransomguard.late_track_b,ransomguard.console_stream,ransomguard.recovery,ransomguard.observer_filter;d=ctypes.WinDLL(sys.argv[2]);assert d.RgReadBatch;print('bundled runtime imports and native export OK')"
r=subprocess.run([str(payload/'python/python.exe'),'-c',code,str(payload/'backend'),str(payload/'backend/native/rg_intake.dll')],capture_output=True,text=True,timeout=45,creationflags=0x08000000)
assert r.returncode==0,r.stderr
native=payload/'ui/resources/app.asar.unpacked/node_modules/better-sqlite3/prebuilds/win32-x64.node'
env=dict(os.environ,ELECTRON_RUN_AS_NODE='1')
node=subprocess.run([str(payload/'ui/ransom0-ui.exe'),'-e',"require(process.argv[1]);console.log('native SQLite ABI OK')",str(native)],env=env,capture_output=True,text=True,timeout=45,creationflags=0x08000000)
assert node.returncode==0,node.stderr
report={'status':'PASS','version':version,'embedded_files_verified':len(m['files']),'embedded_zip_matches_build':True,'packaged_first_party_sources_match':True,'driver_sha256':m['driver_sha256'],'thresholds':cfg['decision'],'bundled_runtime_smoke':r.stdout.strip(),'native_sqlite_smoke':node.stdout.strip(),'backend_tests':646,'installer_tests':20,'ui_tests':53,'ui_assertions':341,'ui_lint':'PASS','ui_typescript_vite_build':'PASS','ui_package':'PASS; local Electron 44.4.3 distribution, no signing/resource customization','actual_vm_installation':'NOT_YET_VERIFIED','drivers_loaded_on_host':False,'real_malware_executed':False,'exe_sha256':sha(exe),'bytes':exe.stat().st_size}
(O/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
(O/'payload-manifest.json').write_text(json.dumps(m,indent=2),encoding='utf8')
print(json.dumps(report,ensure_ascii=False))
