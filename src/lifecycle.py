"""Conservative uninstall: preserve evidence, refuse active or unknown ownership."""
import contextlib, ctypes, hashlib, json, os, sqlite3, subprocess, time
from pathlib import Path

class InstallLock:
    def __enter__(self):
        from ctypes import wintypes as W
        self.k = ctypes.WinDLL('kernel32',use_last_error=True)
        self.k.CreateMutexW.argtypes=[W.LPVOID,W.BOOL,W.LPCWSTR];self.k.CreateMutexW.restype=W.HANDLE
        self.k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];self.k.WaitForSingleObject.restype=W.DWORD
        self.k.ReleaseMutex.argtypes=[W.HANDLE];self.k.CloseHandle.argtypes=[W.HANDLE]
        self.handle=self.k.CreateMutexW(None,False,'Global\\RansomGuard.Install')
        if not self.handle:raise ctypes.WinError(ctypes.get_last_error())
        if self.k.WaitForSingleObject(self.handle,0) not in (0,0x80):
            self.k.CloseHandle(self.handle);raise RuntimeError('다른 설치·제거 작업이 실행 중입니다.')
        return self
    def __exit__(self,*args):
        self.k.ReleaseMutex(self.handle);self.k.CloseHandle(self.handle)

def _count(path, sql):
    with contextlib.closing(sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
        limit=time.monotonic()+4
        db.set_progress_handler(lambda:int(time.monotonic()>limit),1000)
        return db.execute(sql).fetchone()[0]

def plan(receipt, app):
    reasons=[]
    if not receipt or receipt.get('state') not in ('running','installed','uninstall_incomplete'):
        return {'allowed':False,'reasons':['정상 설치 영수증을 확인하지 못했습니다.'],'preserve_history':True}
    base=Path(receipt['runtime']);root=Path(app)/receipt['version']
    if root.resolve().parent != Path(app).resolve() or not root.is_dir() or root.is_symlink():
        reasons.append('설치 경로 소유권을 확인할 수 없습니다.')
    try:
        if _count(base/'observe.sqlite3',"SELECT COUNT(*) FROM response_jobs WHERE state IN ('READY','RUNNING')"):
            reasons.append('분석·복구 작업이 진행 중입니다.')
        if _count(base/'observe.sqlite3',"SELECT COUNT(*) FROM live_response_attempts WHERE state != 'RELEASED'"):
            reasons.append('완료되지 않은 대응 또는 검토 사건이 있습니다.')
        if _count(base/'holds.sqlite3','SELECT COUNT(*) FROM firewall_holds'):
            reasons.append('해제되지 않은 방화벽·검토 hold가 있습니다.')
    except (sqlite3.Error,OSError):
        reasons.append('대응 상태 DB를 확인하지 못해 제거를 중단합니다.')
    # A migrated deployment includes components not owned by this installer.
    if receipt.get('old_paths') and not receipt.get('owns_deployment'):
        reasons.append('기존 수동 설치 구성요소의 소유권을 자동 인수하지 않습니다.')
    return {'allowed':not reasons,'reasons':reasons,'install_root':str(root),'runtime':str(base),
            'preserve_history':True,'preserve_snapshots':True,'preserve_network_policy':True}

def register(engine, receipt):
    root=engine.APP/receipt['version']
    engine.ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RansomGuard.Internal'
New-Item -Path $key -Force|Out-Null
foreach($pair in @(@('DisplayName','Ransom0 내부 시험판'),@('Publisher','RansomGuard University Project'),@('DisplayVersion',$i.version),@('InstallLocation',$i.root),@('DisplayIcon',$i.exe),@('UninstallString',('"'+$i.exe+'" --uninstall')))){
 New-ItemProperty -Path $key -Name $pair[0] -Value $pair[1] -PropertyType String -Force|Out-Null
}
New-ItemProperty -Path $key -Name NoModify -Value 1 -PropertyType DWord -Force|Out-Null
New-ItemProperty -Path $key -Name NoRepair -Value 1 -PropertyType DWord -Force|Out-Null
''',{'version':receipt['version'],'root':str(root),'exe':str(root/'RansomGuard.exe')})

def cleanup_owned_files(root, manifest):
    """Delete only matching package bytes; defer in-use files until reboot."""
    root=Path(root).resolve();removed=[];pending=[];retained=[]
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.MoveFileExW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];k.MoveFileExW.restype=ctypes.c_int
    for relative,want in manifest['files'].items():
        path=root/relative
        if not path.resolve().is_relative_to(root) or path.is_symlink() or any(p.is_symlink() for p in path.parents if p!=root):
            raise ValueError('Unsafe uninstall path')
        if not path.exists():continue
        with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=want:retained.append(relative);continue
        try:path.unlink();removed.append(relative)
        except PermissionError:
            if not k.MoveFileExW(str(path),None,4):raise ctypes.WinError(ctypes.get_last_error())
            pending.append(relative)
    # Keep the manifest and directory as a small audit trail. No recursive
    # deletion of unknown files, VSS state, history or credentials is performed.
    return {'removed_files':len(removed),'reboot_pending_files':pending,'modified_files_preserved':retained}

def uninstall(engine):
    receipt=engine.load(engine.DATA/'installation-receipt.json')
    decision=plan(receipt,engine.APP)
    if not decision['allowed']:raise RuntimeError(' / '.join(decision['reasons']))
    base=Path(receipt['runtime']);root=Path(decision['install_root'])
    manifest=engine.load(root/'payload-manifest.json')
    if not manifest or manifest.get('version')!=receipt['version']:
        raise RuntimeError('Package ownership manifest missing')
    # Validate task actions before disabling any task or touching a service.
    engine.ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
foreach($name in $i.tasks){
 $t=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
 if($t){foreach($a in $t.Actions){if($a.Execute -ne $i.python -or !$a.Arguments.Contains($i.engine)){throw ('Task ownership changed: '+$name)}}}
}''',{'tasks':list(engine.TASKS),'python':receipt['paths']['python'],'engine':str(root/'setup/setup_engine.py')})
    # Refuse an active policy even if its database ownership is missing.
    from ransomguard.firewall_ipc import FirewallIpcClient,FirewallIpcError
    try:
        if FirewallIpcClient(timeout_ms=1500).request('get')['active']:
            raise RuntimeError('활성 방화벽 정책이 있어 제거하지 않았습니다.')
    except (FirewallIpcError,OSError,TimeoutError):
        # Inability to inspect a running daemon must fail closed.
        running=json.loads(engine.ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;[bool](Get-CimInstance Win32_Process|Where-Object ExecutablePath -eq $i.path)|ConvertTo-Json",{'path':receipt['paths']['firewall']}))
        if running:raise RuntimeError('실행 중인 방화벽 정책을 조회하지 못했습니다.')
    receipt.update(state='uninstall_incomplete',uninstall_started=time.time())
    engine.save(engine.DATA/'installation-receipt.json',receipt)
    engine.save(base/'supervisor-maintenance.json',{'until':time.time()+1800,'reason':'uninstall','created_at':time.time()})
    engine.ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;foreach($n in $i.tasks){$t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue;if($t){Disable-ScheduledTask -TaskName $n|Out-Null;Stop-ScheduledTask -TaskName $n}}",{'tasks':list(engine.TASKS)})
    ready=engine.load(base/'observer-ready.json',{})
    receipt['uninstall_counters_before']=ready.get('counter_totals')
    engine.stop_collector(base,ready)
    # Check again after intake/worker stop; never remove protection if a job raced us.
    decision=plan(receipt,engine.APP)
    if not decision['allowed']:raise RuntimeError(' / '.join(decision['reasons']))
    engine.ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
foreach($path in $i.paths){
 foreach($p in @(Get-CimInstance Win32_Process|Where-Object ExecutablePath -eq $path)){
  $again=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId)
  if($again.ExecutablePath -eq $path -and $again.CreationDate -eq $p.CreationDate){
   $failure=$null
   try{$r=Invoke-CimMethod -InputObject $again -MethodName Terminate;if($r.ReturnValue -ne 0){$failure='Termination result '+$r.ReturnValue}}
   catch{$failure=$_.Exception.Message}
   # Electron children may be exiting when the parent's termination returns.
   # Wait for that exact process generation; never signal a reused PID.
   $alive=$true
   for($attempt=0;$attempt -lt 30;$attempt++){
    $now=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId)
    if(!$now -or $now.CreationDate -ne $p.CreationDate){$alive=$false;break}
    Start-Sleep -Milliseconds 100
   }
   if($alive){throw ('Owned process did not exit: '+$p.ProcessId+' '+$path+' '+$failure)}
  }
 }
}''',{'paths':[receipt['paths']['ui'],receipt['paths']['firewall']]})
    for service in reversed(receipt.get('created_services',[])):
        engine.stop_service(service)
        q=subprocess.run(['sc.exe','delete',service],capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if q.returncode not in (0,1060):raise RuntimeError('Driver removal failed: '+service)
    from release_policy import driver_store
    for inf in reversed(receipt.get('driver_store_packages',[])):
        value=driver_store('uninstall',inf)
        receipt['reboot_required']=receipt.get('reboot_required',False) or value['reboot_required']
    engine.ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
foreach($name in $i.tasks){if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $name -Confirm:$false}}
foreach($label in @('Ransom0.lnk','Ransom0_install.lnk','RansomGuard.lnk')){
$link=Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $label
if(Test-Path -LiteralPath $link){$w=New-Object -ComObject WScript.Shell;if($w.CreateShortcut($link).TargetPath -in @($i.exe,(Join-Path $i.root 'Ransom0.exe'))){Remove-Item -LiteralPath $link}}
}
$key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RansomGuard.Internal'
if(Test-Path $key){if((Get-ItemProperty $key).InstallLocation -eq $i.root){Remove-Item -LiteralPath $key}}
''',{'tasks':list(engine.TASKS),'root':str(root),'exe':str(root/'RansomGuard.exe')})
    receipt['cleanup']=cleanup_owned_files(root,manifest)
    receipt['reboot_required']=receipt.get('reboot_required',False) or bool(receipt['cleanup']['reboot_pending_files'])
    receipt.update(state='uninstalled',uninstalled_at=time.time(),
        uninstall_counters_after=engine.load(base/'observer-ready.json',{}).get('counter_totals'),
        retained=['UI history','response databases','VSS snapshots','JEV key','network policy'],
        files_retained=str(root))
    engine.save(engine.DATA/'installation-receipt.json',receipt)
    return receipt
