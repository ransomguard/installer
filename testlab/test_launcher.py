"""Exercise shipped menu mapping and native argv in Windows PowerShell 5.1.

Only prints arguments; no workloads, installed services, or VM changes.
"""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path

class LauncherArguments(unittest.TestCase):
    def test_all_menu_profiles_preserve_native_arguments(self):
        source=Path(__file__).with_name('Start-TestLab.ps1').read_text(encoding='utf-8-sig')
        start=source.index('    [string[]]$testArgs=')
        mapping=source[start:source.index('    if (!$testArgs.Count)',start)]
        expected={1:['idle'],2:['burst','--count','12000'],3:['burst','--count','120000'],4:['mixed'],5:['process'],6:['prepare'],7:['recovery'],8:['track-a'],9:['track-b','--allow-jev'],10:['suite'],11:['kernel-block']}
        with tempfile.TemporaryDirectory(prefix='Ransom0 launcher ') as folder:
            base=Path(folder); probe=base/'argument probe.py'
            probe.write_text('import sys,json;print(json.dumps(sys.argv[1:]))',encoding='utf8')
            quote=lambda s:"'"+str(s).replace("'","''")+"'"
            script=base/'check.ps1'
            script.write_text("$ErrorActionPreference='Stop'\n$python="+quote(sys.executable)+"\nforeach($choice in @('1','2','3','4','5','6','7','8','9','10','11','invalid')) {\n"+mapping+"if (!$testArgs.Count) { continue }\n& $python "+quote(probe)+" @testArgs --confirm-test\nif($LASTEXITCODE){throw 'Probe failed'}\n}\n",encoding='utf-8-sig')
            p=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script)],capture_output=True,text=True,timeout=45)
            self.assertEqual(p.returncode,0,p.stderr)
            actual=[json.loads(line) for line in p.stdout.splitlines() if line.strip()]
            self.assertEqual(actual,[args+['--confirm-test'] for args in expected.values()])

if __name__=='__main__':unittest.main()
