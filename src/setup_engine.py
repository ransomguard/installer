"""Offline prototype installer. Commands only enter Windows from explicit main()."""
import argparse, ast, ctypes, hashlib, json, os, re, shutil, subprocess, sys, time, uuid
from pathlib import Path

VERSION='0.6.0-preview.24'
APP=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'RansomGuard'
DATA=Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'RansomGuard'
TASKS=('RansomGuard-InteractiveStartup','RansomGuard-PassiveSupervisor','RansomGuard-HourlySnapshot','RansomGuard-SnapshotRetention')

def ps(code, data=None, timeout=45):
    prefix="$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
    p=subprocess.run([os.path.join(os.environ.get('SystemRoot',r'C:\Windows'),'System32/WindowsPowerShell/v1.0/powershell.exe'),
        '-NoProfile','-NonInteractive','-Command',prefix+code+'; exit 0'],input=json.dumps(data or {}),
        text=True,encoding='utf-8',capture_output=True,timeout=timeout,creationflags=0x08000000)
    if p.returncode:raise RuntimeError(p.stderr.strip()[-1800:] or 'PowerShell exit code '+str(p.returncode))
    return p.stdout.lstrip('\ufeff').strip()

def load(path, default=None):
    try:return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except FileNotFoundError:return default

def save(path,value):
    from ransomguard.protection_setup import save_json
    save_json(path,value)

def trace(message):print(message,flush=True)

def legacy_paths(base):
    conf=load(base/'installation.json')
    if conf:return conf
    # Parse the old launcher's constants without executing its code.
    vals={}
    def val(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):return node.value
        if isinstance(node,ast.Name) and node.id in vals:return vals[node.id]
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='Path' and len(node.args)==1:return val(node.args[0])
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Div):return str(Path(val(node.left))/val(node.right))
        raise ValueError('Unsupported legacy path expression')
    for node in ast.parse((base/'Start-RansomGuard.py').read_text(encoding='utf-8-sig')).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('BASE','ROOT','PY','UI','DAEMON'):
            vals[node.targets[0].id]=val(node.value)
    return dict(schema=1,evidence_mode='test',**{k:vals[v] for k,v in [('recovery_root','ROOT'),('python','PY'),('ui','UI'),('firewall','DAEMON')]})

def discover():
    receipt=load(DATA/'installation-receipt.json')
    if receipt and receipt.get('state') not in ('uninstalled','fresh_install_failed'):
        return Path(receipt['runtime']),receipt['paths'],receipt
    text=ps("$t=Get-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup' -ErrorAction SilentlyContinue;if($t){$t.Actions[0].Arguments}")
    match=re.search(r'"([^"\r\n]*Start-RansomGuardAtLogon\.ps1)"',text,re.I)
    if match:
        base=Path(match.group(1)).parent
        return base,legacy_paths(base),None
    return DATA/'Runtime',None,None

def inspect(payload):
    payload=Path(payload)
    info=json.loads(ps("@{admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);os=(Get-CimInstance Win32_OperatingSystem|Select-Object BuildNumber,OSArchitecture);computer=(Get-CimInstance Win32_ComputerSystem|Select-Object Manufacturer,Model);sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;drivers=@(Get-CimInstance Win32_SystemDriver|Where-Object Name -in @('Anti_Ransom_Driver','Anti_Ransom_FsFilter')|Select-Object Name,State,PathName)}|ConvertTo-Json -Depth 4 -Compress"))
    base,old,receipt=discover()
    manifest=load(payload/'payload-manifest.json')
    if not manifest or manifest.get('channel') not in ('isolated-lab','internal-test','internal-preview'):raise ValueError('A reviewed release manifest is required')
    info.update(runtime=str(base),existing=bool(old),channel=manifest['channel'],version=VERSION,
                general_pc_ready=False,signing_reason='Ordinary PC installation requires verified Microsoft signatures. Internal testing does not require an assigned altitude.')
    from readiness import collect,blockers
    info['readiness']=collect(payload)
    info['installation_blockers']=blockers(info['readiness'],manifest['channel'])
    return info

def verify_payload(payload):
    manifest=load(payload/'payload-manifest.json')
    if not manifest or manifest.get('schema')!=1:raise ValueError('Payload manifest missing')
    for name,want in manifest['files'].items():
        path=payload/name
        if not path.resolve().is_relative_to(payload.resolve()) or path.is_symlink():raise ValueError('Unsafe package path')
        if not path.is_file():raise ValueError('Package file missing: '+name)
        with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=want:
            raise ValueError('Package verification failed: '+name)
    return manifest

def register_tasks(base, paths, backup):
    from ransomguard.snapshot_settings import interval_minutes
    from ransomguard.snapshots import default_state_db
    background_python=Path(paths['python']).with_name('pythonw.exe')
    if not background_python.is_file():raise RuntimeError('Background Python runtime is missing')
    data=dict(base=str(base),python=str(background_python),engine=str(APP/VERSION/'setup/setup_engine.py'),backup=str(backup),snapshot_minutes=interval_minutes(default_state_db()))
    ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$old=Get-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup' -ErrorAction SilentlyContinue
$sid=if($old){$old.Principal.UserId}else{[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
if($sid -in @('SYSTEM','S-1-5-18')){throw 'Interactive administrator must install this package'}
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$settingsStart=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
foreach($name in @('RansomGuard-InteractiveStartup','RansomGuard-PassiveSupervisor','RansomGuard-HourlySnapshot','RansomGuard-SnapshotRetention')){
 $t=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
 if($t){Export-ScheduledTask -TaskName $name|Set-Content -LiteralPath (Join-Path $i.backup ($name+'.xml')) -Encoding UTF8}
}
$definitions=@(
 @{Name='RansomGuard-InteractiveStartup';Command='start';Trigger=(New-ScheduledTaskTrigger -AtLogOn -User $sid);Settings=$settingsStart},
 @{Name='RansomGuard-PassiveSupervisor';Command='watch';Trigger=(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1));Settings=$settings},
 @{Name='RansomGuard-HourlySnapshot';Command='snapshot';Trigger=(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($i.snapshot_minutes) -RepetitionInterval (New-TimeSpan -Minutes $i.snapshot_minutes));Settings=$settings},
 @{Name='RansomGuard-SnapshotRetention';Command='retention';Trigger=(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5));Settings=$settings})
foreach($d in $definitions){
 $arg='"'+$i.engine+'" '+$d.Command+' --runtime "'+$i.base+'"'
 $a=New-ScheduledTaskAction -Execute $i.python -Argument $arg -WorkingDirectory $i.base
 Register-ScheduledTask -TaskName $d.Name -Action $a -Trigger $d.Trigger -Principal $principal -Settings $d.Settings -Force|Out-Null
}
''',data)

def ensure_jev_transport(base, installroot):
    """An empty key must not make the dashboard's future key setup unusable."""
    transport=load(base/'jev-transport.json')
    if transport is None:
        transport={'endpoint':'https://api.typesafe.ai','bridge':str(installroot/'bridge/RansomGuard.JevBridge.exe')}
        save(base/'jev-transport.json',transport)
    return transport


def prepare_network(channel, old, request, bridge, backup, runner):
    """Installation never changes firewall profiles, exceptions, or hosts mappings.

    Even legacy jev_only_network requests cannot re-enable install-time isolation.
    Incident containment belongs to the response coordinator's durable holds.
    """
    return {'preserved_existing':True,'configured':False,'mode':'incident_response_only'}


def install(payload, request):
    payload=Path(payload).resolve();manifest=verify_payload(payload);info=inspect(payload)
    if manifest.get('version')!=VERSION:raise ValueError('Installer and payload versions differ')
    if not info['admin']:raise ValueError('Administrator privileges required')
    from readiness import require_ready
    require_ready(info['readiness'],manifest['channel'])
    from release_policy import check_channel
    trust=check_channel(manifest,info,request,payload,ps)
    if manifest['channel']!='isolated-lab' and request.get('acknowledge_pc_wide_containment') is not True:
        raise ValueError('자동 대응 시 이 PC 전체의 통신이 제한될 수 있음에 동의해야 합니다.')
    base,old,receipt=discover()
    previous=load(DATA/'installation-receipt.json',{})
    if previous.get('state')=='uninstalled' and previous.get('reboot_required'):
        pending=json.loads(ps("@((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)|ConvertTo-Json -Compress") or '[]')
        if isinstance(pending,str):pending=[pending]
        prefix=str(APP/previous['version']).lower()
        if any(isinstance(x,str) and prefix in x.lower() for x in pending):
            raise RuntimeError('이전 제거의 파일 정리가 예약돼 있습니다. Windows 재부팅 후 다시 설치하세요.')
    from ransomguard.protection_setup import configure_scope,refresh,validate_folder
    # Recovery scope is selected later in dashboard Settings; upgrades preserve it.
    existing_scope=load(base/'protection.json',{})
    folder=existing_scope.get('protected_root','');volume=existing_scope.get('volume_root','')
    installroot=APP/VERSION
    if installroot.exists():
        oldmanifest=load(installroot/'payload-manifest.json')
        if oldmanifest!=manifest:raise ValueError('This version directory differs; a new version is required')
    # An existing deployment may be upgraded only with the reviewed same drivers.
    expected=manifest['driver_sha256'];present={x['Name']:x for x in info['drivers']}
    for name,item in present.items():
        raw=item['PathName'];raw=raw[4:] if raw.startswith('\\??\\') else raw
        if hashlib.sha256(Path(raw).read_bytes()).hexdigest()!=expected[name]:raise ValueError('Existing kernel driver differs; controlled driver upgrade is required')
    if old:
        import sqlite3
        with sqlite3.connect((base/'observe.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=3) as db:
            if db.execute("SELECT 1 FROM response_jobs WHERE state IN ('READY','RUNNING') LIMIT 1").fetchone():
                raise RuntimeError('An incident response is active; install after it finishes')
    trace('검사 완료. 기존 기록과 정책을 유지하며 프로그램을 배치합니다.')
    installroot.parent.mkdir(parents=True,exist_ok=True)
    if not installroot.exists():shutil.copytree(payload,installroot)
    else:
        # A completed uninstall retains the manifest/history. Reinstall fills
        # missing package files without overwriting changed or running bytes.
        for relative,want in manifest['files'].items():
            target=installroot/relative
            if not target.resolve().is_relative_to(installroot.resolve()) or target.is_symlink():raise ValueError('Unsafe installed path')
            if target.exists():
                with target.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
                if actual!=want:raise ValueError('Installed package differs; use a new version')
            else:
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(payload/relative,target)
    base.mkdir(parents=True,exist_ok=True);backup=base/'install-backups'/str(int(time.time()));backup.mkdir(parents=True)
    save(base/'supervisor-maintenance.json',{'until':time.time()+1800,'reason':'verified integrated installer','created_at':time.time()})
    # Executable task files and state must not be writable by unelevated users.
    ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json; & icacls.exe $i.base /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null;if($LASTEXITCODE){throw 'Runtime ACL failed'}",{'base':str(base)})
    paths=dict(schema=1,evidence_mode='test',recovery_root=str(installroot/'backend'),python=str(installroot/'python/python.exe'),
        ui=str(installroot/'ui/ransom0-ui.exe'),
        firewall=old['firewall'] if old else str(installroot/'firewall/r0-fw-daemon.exe'))
    journal={'version':VERSION,'runtime':str(base),'paths':paths,'old_paths':old,'backup':str(backup),
             'created_services':list((receipt or {}).get('created_services',[])),
             'driver_store_packages':list((receipt or {}).get('driver_store_packages',[])),
             'owns_deployment':bool((receipt or {}).get('owns_deployment')) if old else True,
             'installed_at':time.time(),'state':'preparing','preserve_history':True,'channel':manifest['channel'],'trust':trust}
    save(DATA/'installation-receipt.json',journal)
    if old:
        # Enable a session-bound drain in the old worker through its existing
        # hot-reload protocol. Resident intake and driver ABI stay unchanged.
        oldsource=Path(old['recovery_root'])/'ransomguard'
        for name in ('console_stream.py','installer_drain.py','cli.py'):
            if (oldsource/name).exists():shutil.copy2(oldsource/name,backup/('old-'+name))
            shutil.copy2(installroot/'backend/ransomguard'/name,oldsource/name)
        from ransomguard.resident import request_reload
        request_reload(base/'observer-ready.json',oldsource)
        deadline=time.monotonic()+45
        from ransomguard.resident import source_revision
        revision=source_revision(oldsource)
        while time.monotonic()<deadline:
            r=load(base/'observer-ready.json',{})
            if r.get('worker_revision')==revision and r.get('worker_state')=='running':break
            time.sleep(.2)
        else:raise RuntimeError('Drain worker preparation failed; old collector was not stopped')
        # Freeze file intake before a bounded cooperative collector stop.
        # Exact coverage gap and before/after counters are kept in the receipt.
        journal['before']=load(base/'observer-ready.json');journal['coverage_gap_started']=time.time()
        p=subprocess.run(['sc.exe','stop','Anti_Ransom_FsFilter'],capture_output=True,timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if p.returncode not in (0,1062):raise RuntimeError('Cannot pause filter for controlled installation')
        # sc stop can return STOP_PENDING. Confirm STOPPED before pausing
        # process callbacks, otherwise continuous writes could defeat draining.
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            q=subprocess.run(['sc.exe','query','Anti_Ransom_FsFilter'],capture_output=True,timeout=10,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if b'STOPPED' in q.stdout:break
            time.sleep(.2)
        else:raise RuntimeError('File filter stop not confirmed')
        save(base/'observer-ready.install-stop.json',{'pid':journal['before']['pid'],'session':journal['before']['resident_session'],
            'file_filter_stopped':True,'expires':time.time()+90})
        (base/'observer-ready.stop').write_text('integrated-install')
        deadline=time.monotonic()+60
        pid=(journal['before'] or {}).get('pid')
        while pid and time.monotonic()<deadline:
            alive=ps('$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;[bool](Get-Process -Id $i.pid -ErrorAction SilentlyContinue)',{'pid':pid})
            if alive.lower()=='false':break
            time.sleep(.5)
        else:
            if pid:raise RuntimeError('Collector did not stop cooperatively; no force termination performed')
        journal['stopped']=load(base/'observer-ready.json');save(DATA/'installation-receipt.json',journal)
        # Use this release's UI, not the previous installation's executable.
        # The userData database remains at the existing app identity/path.
        ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$items=@(Get-Process -Name 'ransom0-ui' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $i.path })
foreach($p in $items){if($p.MainWindowHandle -ne 0){$p.CloseMainWindow()|Out-Null}}
Start-Sleep -Seconds 2
foreach($p in $items){$p.Refresh();if(!$p.HasExited -and $p.Path -eq $i.path){$p.Kill()}}
''',{'path':old['ui']})
    elif manifest['channel']=='internal-preview':
        from release_policy import driver_store
        for name in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter'):
            inf=installroot/'drivers'/name/(name+'.inf')
            result=driver_store('install',inf)
            journal['driver_store_packages'].append(str(inf))
            journal['reboot_required']=journal.get('reboot_required',False) or result['reboot_required']
            save(DATA/'installation-receipt.json',journal)
        if journal.get('reboot_required'):
            raise RuntimeError('Windows driver installation requires reboot; no protection-ready claim was made')
    else:
        # Lab installation uses already-trusted embedded signatures. Windows
        # still enforces them; never set TESTSIGNING or import certificates.
        for name in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter'):
            binary=installroot/'drivers'/(name+'.sys')
            args=['sc.exe','create',name,'type=','filesys' if name.endswith('FsFilter') else 'kernel','start=','demand','binPath=',str(binary)]
            if name.endswith('FsFilter'):args+=['depend=','FltMgr','group=','FSFilter Activity Monitor']
            p=subprocess.run(args,capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if p.returncode:raise RuntimeError('Driver service registration failed: '+name)
            journal['created_services'].append(name);save(DATA/'installation-receipt.json',journal)
        import winreg
        for suffix in ('Instances','Parameters\\Instances'):
            root='SYSTEM\\CurrentControlSet\\Services\\Anti_Ransom_FsFilter\\'+suffix
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,root) as k:winreg.SetValueEx(k,'DefaultInstance',0,winreg.REG_SZ,'RansomGuard Instance')
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,root+r'\RansomGuard Instance') as k:
                winreg.SetValueEx(k,'Altitude',0,winreg.REG_SZ,'385090');winreg.SetValueEx(k,'Flags',0,winreg.REG_DWORD,0)
        # Validate Windows signature/load enforcement before modifying the
        # fresh VM's network policy. Never enable test signing automatically.
        p=subprocess.run(['sc.exe','start','Anti_Ransom_Driver'],capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if p.returncode not in (0,1056):
            raise RuntimeError('Windows에서 시험 드라이버를 로드하지 못했습니다 (코드 '+str(p.returncode)+'). 일반 PC에는 Microsoft 서명 패키지가 필요합니다. 보안 설정을 자동 변경하지 않았습니다.')
    templates=installroot/'backend/integration/windows'
    for name in ('installation_paths.py','Start-RansomGuard.py','Start-RansomGuard.ps1','Start-RansomGuard.cmd','Watch-RansomGuard.py','Watch-RansomGuard.ps1'):
        if (base/name).exists():shutil.copy2(base/name,backup/name)
        shutil.copy2(templates/name,base/name)
    if (base/'installation.json').exists():shutil.copy2(base/'installation.json',backup/'installation.json')
    save(base/'installation.json',paths)
    for name in ('live-response-profile.json','protection.json','protected-manifest.json'):
        if (base/name).exists():shutil.copy2(base/name,backup/name)
    from ransomguard.protection_setup import ensure_response_database
    ensure_response_database(base)
    preparation=load(base/'protection-status.json',{'ready':False,'reason':'scope_not_configured','detail':'대시보드 설정에서 보호·복구 폴더를 선택해 주세요.'})
    if not existing_scope:
        save(base/'protection-status.json',preparation)
    config=load(base/'response-config.json') or load(installroot/'backend/config/example.json')
    if existing_scope:config['recovery'].update(protected_root=folder,volume_root=volume)
    save(base/'response-config.json',config)
    save(base/'scope-settings-enabled.json',{'schema_version':1})
    save(base/'scope-authorization.json',dict(schema_version=1,authorized_isolated_lab=manifest['channel']=='isolated-lab',
        authorized_internal_test=manifest['channel']!='isolated-lab',acknowledged_pc_wide_containment=request.get('acknowledge_pc_wide_containment') is True,tracks=['A','B']))
    from ransomguard.observer_filter import _query_dos_device
    transport=ensure_jev_transport(base,installroot)
    if request.get('api_key'):
        bridge=Path(transport['bridge']) if transport else installroot/'bridge/RansomGuard.JevBridge.exe'
        p=subprocess.run([str(bridge),'--import-key'],input=request['api_key'],text=True,capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if p.returncode:raise RuntimeError('JEV key import failed; key was not logged')
        request['api_key']='';transport={'endpoint':'https://api.typesafe.ai','bridge':str(bridge)};save(base/'jev-transport.json',transport)
    key_ready=False
    if transport:
        check=subprocess.run([transport['bridge'],'--check-key'],capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        key_ready=check.returncode==0
        if not key_ready:trace('JEV 키를 이 Windows에서 읽을 수 없어 자동 대응을 활성화하지 않습니다.')
    journal['network_setup']=prepare_network(manifest['channel'],old,request,installroot/'bridge/RansomGuard.JevBridge.exe',backup,ps)
    # API key availability is not a claim of successful external authentication.
    # Normal connectivity uses the existing OS policy; isolation is incident-driven.
    network_ready=key_ready
    if preparation['ready'] and network_ready:
        save(base/'live-response-profile.json',dict(schema_version=1,authorized_isolated_lab=manifest['channel']=='isolated-lab',
            authorized_internal_test=manifest['channel']!='isolated-lab',acknowledged_pc_wide_containment=request.get('acknowledge_pc_wide_containment') is True,tracks=['A','B'],
            nt_path_prefix=_query_dos_device(folder[:2])+folder[2:],config=str(base/'response-config.json'),manifest=str(base/'protected-manifest.json')))
    else:
        # The previous scope is backed up above. It must never silently stay
        # authorized after the operator selected a different, unready folder.
        (base/'live-response-profile.json').unlink(missing_ok=True)
        trace('복구 기준 또는 JEV 키가 준비되지 않아 관찰 모드로 설치됩니다.')
    journal['task_registration_started']=True;save(DATA/'installation-receipt.json',journal)
    register_tasks(base,paths,backup)
    # Dashboard uses the integrated elevated startup; management is a separate link.
    ps(r'''$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$w=New-Object -ComObject WScript.Shell
$desktop=[Environment]::GetFolderPath('CommonDesktopDirectory')
$s=$w.CreateShortcut((Join-Path $desktop 'Ransom0.lnk'));$s.TargetPath=$i.dashboard;$s.Arguments='';$s.WorkingDirectory=Split-Path $i.dashboard;$s.IconLocation=$i.dashboard+',0';$s.Save()
$s=$w.CreateShortcut((Join-Path $desktop 'Ransom0_install.lnk'));$s.TargetPath=$i.exe;$s.Arguments='--manage';$s.WorkingDirectory=Split-Path $i.exe;$s.IconLocation=$i.exe+',0';$s.Save()
foreach($name in @('RansomGuard.lnk','랜섬제로.lnk')) {
 $old=Join-Path $desktop $name
 if(Test-Path -LiteralPath $old) {
  $link=$w.CreateShortcut($old)
  if($link.TargetPath -like ((Join-Path $env:ProgramFiles 'RansomGuard')+'\*\RansomGuard.exe') -and $link.Arguments -eq '--manage') { Remove-Item -LiteralPath $old }
 }
}
''',{'exe':str(installroot/'RansomGuard.exe'),'dashboard':str(installroot/'Ransom0.exe')})
    journal.update(state='installed',recovery=preparation,network_ready=network_ready);save(DATA/'installation-receipt.json',journal)
    from lifecycle import register
    register(sys.modules[__name__],journal)
    ps("Start-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup'")
    trace('시작 작업을 등록했습니다. 로그인된 사용자 세션에서 수집기와 대시보드가 시작됩니다.')
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        ready=load(base/'observer-ready.json',{})
        if ready.get('worker_state')=='running' and ready.get('counter_totals') and time.time()-ready.get('observed_at',0)<15 and ready.get('pid')!=(journal.get('before') or {}).get('pid'):
            journal.update(state='running',after=ready,coverage_gap_ended=time.time());save(DATA/'installation-receipt.json',journal);break
        time.sleep(1)
    else:raise RuntimeError('Installation saved but startup not verified; inspect status and startup logs')
    (base/'supervisor-maintenance.json').unlink(missing_ok=True)
    return journal

def stop_service(name):
    if name not in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter'):raise ValueError('Unexpected service')
    p=subprocess.run(['sc.exe','stop',name],capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if p.returncode not in (0,1060,1062):raise RuntimeError('Could not stop '+name)
    if p.returncode==1060:return
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        p=subprocess.run(['sc.exe','query',name],capture_output=True,timeout=10,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if p.returncode==1060 or b'STOPPED' in p.stdout:return
        time.sleep(.25)
    raise RuntimeError('Service stop not confirmed: '+name)

def stop_collector(base,ready):
    stop_service('Anti_Ransom_FsFilter')
    pid=ready.get('pid')
    if not pid:return
    # Confirm both executable and exact runtime before issuing a bound stop.
    data=json.loads(ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$i.pid);if($p){@{path=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress}else{'null'}",{'pid':pid}))
    if not data:return
    expected=load(base/'installation.json')['python']
    if data['path'].lower()!=expected.lower() or str(base/'observe.sqlite3').lower() not in data['command'].lower():
        raise RuntimeError('Collector identity changed; no process was terminated')
    save(base/'observer-ready.install-stop.json',{'pid':pid,'session':ready['resident_session'],'file_filter_stopped':True,'expires':time.time()+90})
    (base/'observer-ready.stop').write_text('uninstall')
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        if ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;[bool](Get-Process -Id $i.pid -ErrorAction SilentlyContinue)",{'pid':pid}).lower()=='false':return
        time.sleep(.3)
    raise RuntimeError('Collector did not stop cooperatively; no forced termination performed')

def main():
    for stream in (sys.stdin,sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    p=argparse.ArgumentParser();p.add_argument('command',choices=('inspect','install','uninstall','plan-uninstall','status','start','watch','snapshot','retention'));p.add_argument('--payload');p.add_argument('--runtime');a=p.parse_args()
    payload=Path(a.payload) if a.payload else Path(__file__).resolve().parents[1]
    base=Path(a.runtime) if a.runtime else discover()[0]
    if a.command=='inspect':result=inspect(payload)
    elif a.command=='plan-uninstall':
        from lifecycle import plan
        result=plan(load(DATA/'installation-receipt.json'),APP)
    elif a.command=='uninstall':
        from lifecycle import uninstall,InstallLock
        with InstallLock():result=uninstall(sys.modules[__name__])
    elif a.command=='install':
        started=time.time()
        from lifecycle import InstallLock
        with InstallLock():
            try:
                result=install(payload,json.load(sys.stdin))
            except Exception:
                receipt=load(DATA/'installation-receipt.json',{})
                if receipt.get('installed_at',0)>=started and receipt.get('old_paths'):
                    b=Path(receipt['runtime']);bak=Path(receipt['backup'])
                    # Restore only installer-owned launcher/config backups. Never
                    # roll back the event database, incident state, or snapshots.
                    for name in ('installation_paths.py','Start-RansomGuard.py','Start-RansomGuard.ps1','Start-RansomGuard.cmd',
                                 'Watch-RansomGuard.py','Watch-RansomGuard.ps1','installation.json','live-response-profile.json','protection.json','protected-manifest.json'):
                        if (bak/name).is_file():shutil.copy2(bak/name,b/name)
                    oldsource=Path(receipt['old_paths']['recovery_root'])/'ransomguard'
                    for name in ('console_stream.py','installer_drain.py','cli.py'):
                        if (bak/('old-'+name)).is_file():shutil.copy2(bak/('old-'+name),oldsource/name)
                    try:
                        ps("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;Get-ChildItem -LiteralPath $i.backup -Filter 'RansomGuard-*.xml'|ForEach-Object{Register-ScheduledTask -TaskName $_.BaseName -Xml (Get-Content -LiteralPath $_.FullName -Raw) -Force|Out-Null}",{'backup':str(bak)})
                        ps("Start-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup'")
                    except Exception as rollback_error:receipt['rollback_error']=str(rollback_error)
                    receipt.update(state='installation_failed_previous_start_requested',paths=receipt['old_paths']);save(DATA/'installation-receipt.json',receipt)
                    (b/'supervisor-maintenance.json').unlink(missing_ok=True)
                elif receipt.get('installed_at',0)>=started:
                    # Fresh installation failure is recorded truthfully. Leave
                    # evidence and any stricter network policy intact for review.
                    if receipt.get('task_registration_started'):
                        # Late startup failures can leave live workers or holds.
                        # Use the same ownership/incident/drain checks as uninstall.
                        try:
                            from lifecycle import uninstall
                            receipt['state']='installed';save(DATA/'installation-receipt.json',receipt)
                            receipt=uninstall(sys.modules[__name__])
                            receipt['failed_install_rolled_back']=True
                        except Exception as rollback_error:
                            receipt=load(DATA/'installation-receipt.json',receipt)
                            receipt.update(state='fresh_install_failed_attention',rollback_error=str(rollback_error))
                    else:
                        for service in reversed(receipt.get('created_services',[])):
                            stop_service(service)
                            subprocess.run(['sc.exe','delete',service],capture_output=True,timeout=20,check=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                        from release_policy import driver_store
                        for inf in reversed(receipt.get('driver_store_packages',[])):
                            driver_store('uninstall',inf)
                        receipt['state']='fresh_install_failed'
                    save(DATA/'installation-receipt.json',receipt)
                raise
    elif a.command=='status':
        from ransomguard.health_report import report
        result=report(base)
    elif a.command in ('start','watch'):
        sys.path.insert(0,str(base))
        import runpy
        runpy.run_path(str(base/('Start-RansomGuard.py' if a.command=='start' else 'Watch-RansomGuard.py')),run_name='__main__');return
    elif a.command=='snapshot':
        from ransomguard.protection_setup import refresh
        result=refresh(base,create_snapshot=True) if (base/'protection.json').exists() else {'ready':False,'reason':'scope_not_configured'}
    else:
        from ransomguard.snapshots import default_state_db
        from ransomguard.snapshot_retention import SnapshotRetention,load_config
        from ransomguard.recovery import volume_id_for_root
        state=default_state_db();cfg=load(base/'protection.json')
        from ransomguard.scope_settings import scope_lock
        with scope_lock(base):
            result=SnapshotRetention(state,load_config(state)).run(volume_id_for_root(cfg['volume_root']),apply=True) if cfg else {'skipped':'scope_not_configured'}
    print(json.dumps(result,ensure_ascii=False,default=str))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('ERROR: '+str(error),file=sys.stderr,flush=True);sys.exit(1)
