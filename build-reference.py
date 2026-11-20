"""Candidate bundle. --signed-drivers requires actual Microsoft-signed files."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys,zipfile,uuid
B=Path(__file__).resolve().parent;ROOT=B.parents[1];P=B/'payload'
parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group();group.add_argument('--signed-drivers',type=Path);group.add_argument('--test-pc',action='store_true');parser.add_argument('--output',type=Path);parser.add_argument('--ui-asar',type=Path);args=parser.parse_args()
channel='internal-preview' if args.signed_drivers else 'internal-test' if args.test_pc else 'isolated-lab'
version='0.6.0-preview.19'
P=B/('staging-'+version+'-'+uuid.uuid4().hex[:8])
def digest(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def copytree(src,dst):
    shutil.copytree(src,dst,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','.venv','*.egg-info','.git','dist','build','*.status.json'))
P.mkdir(exist_ok=True)
baseline=ROOT/'work/prototype-installer-20261118/payload'
for name in ('python','ui','firewall','bridge'):copytree(baseline/name,P/name)
if args.ui_asar:
    shutil.copy2(args.ui_asar,P/'ui/resources/app.asar')
    unpacked=Path(str(args.ui_asar)+'.unpacked')
    if not unpacked.is_dir():raise SystemExit('Matching app.asar.unpacked is required')
    target=P/'ui/resources/app.asar.unpacked'
    assert target.resolve().is_relative_to(P.resolve()) and P.resolve().is_relative_to(B.resolve())
    if target.exists():shutil.rmtree(target)
    shutil.copytree(unpacked,target)
from build_intake import build as build_intake
build_intake()
copytree(B/'backend',P/'backend')
(P/'setup').mkdir(exist_ok=True)
for f in (B/'src').glob('*.py'):shutil.copy2(f,P/'setup'/f.name)
(P/'drivers').mkdir(exist_ok=True)
for name,folder in [('Anti_Ransom_Driver','Core'),('Anti_Ransom_FsFilter','Filter')]:
    if args.signed_drivers:
        source=args.signed_drivers/folder
        if not all((source/(name+ext)).is_file() for ext in ('.sys','.inf','.cat')):raise SystemExit('Incomplete signed package: '+folder)
        copytree(source,P/'drivers'/name)
    else:shutil.copy2(B/'drivers'/folder/(name+'.sys'),P/'drivers'/(name+'.sys'))
compiler=r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
compile_args=[compiler,'/win32icon:'+str(B/'assets/Ransom0.ico'),'/nologo','/target:winexe','/platform:x64','/win32manifest:'+str(B/'src/app.manifest'),
 '/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll','/r:System.IO.Compression.dll']
subprocess.run(compile_args+['/out:'+str(P/'RansomGuard.exe'),str(B/'src/Manager.cs')],check=True)
subprocess.run([compiler,'/nologo','/target:exe','/platform:x64','/r:System.Windows.Forms.dll','/r:System.Web.Extensions.dll',
 '/out:'+str(P/'RansomGuard-Check.exe'),str(B/'src/Readiness.cs')],check=True)
subprocess.run([compiler,'/nologo','/target:exe','/platform:x64','/r:System.Security.dll','/r:System.Web.Extensions.dll',
 '/out:'+str(P/'bridge/RansomGuard.JevBridge.exe'),str(B/'backend/integration/windows/JevBridge.cs')],check=True)
files={str(p.relative_to(P)).replace('\\','/'):digest(p) for p in sorted(P.rglob('*')) if p.is_file() and p.name!='payload-manifest.json' and '__pycache__' not in p.parts}
manifest={'schema':1,'version':version,'channel':channel,'assigned_altitude':False,'distribution':'non-public internal testing only',
 'driver_sha256':{name:digest(P/'drivers'/name/(name+'.sys') if args.signed_drivers else P/'drivers'/(name+'.sys')) for name in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter')},'files':files}
if args.signed_drivers:
    sys.path.insert(0,str(B/'src'))
    from release_policy import check_channel
    from setup_engine import ps
    check_channel(manifest,{}, {'internal_test':True},P,ps)
(P/'payload-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
zip_path=B/('payload-'+version+'-'+channel+'.zip')
with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED,compresslevel=5) as z:
    for name in list(files)+['payload-manifest.json']:z.write(P/name,name)
out=args.output or ROOT/'outputs/school-demo-20261118';out.mkdir(parents=True,exist_ok=True)
exe=out/('Ransom0-Setup.exe' if args.test_pc else 'Ransom0-'+('Internal' if args.signed_drivers else 'Lab')+'-Setup.exe')
subprocess.run(compile_args+['/resource:'+str(zip_path)+',payload.zip','/out:'+str(exe),str(B/'src/Manager.cs')],check=True)
report={'file':str(exe),'bytes':exe.stat().st_size,'sha256':digest(exe),'version':version,'channel':channel,'payload_files':len(files),
 'payload':str(P),'zip':str(zip_path),'ui_asar_sha256':digest(P/'ui/resources/app.asar'),'baseline_ui_unchanged':digest(P/'ui/resources/app.asar')==digest(baseline/'ui/resources/app.asar')}
shutil.copy2(P/'RansomGuard-Check.exe',out/'Ransom0-Check.exe')
(out/('build-test-pc.json' if args.test_pc else 'build.json')).write_text(json.dumps(report,indent=2));print(json.dumps(report))

