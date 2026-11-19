"""Bounded, local Ransom0 verification. Never encrypts or traverses user files."""
import argparse, ctypes, hashlib, json, os, sqlite3, subprocess, sys, time, uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

HOME = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'Ransom0TestLab'
SCOPE = HOME / 'Protected'
NAMES = ['document-%02d.txt' % n for n in range(12)]

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def safe_tree(path):
    path = Path(path).absolute()
    for p in [path, *path.parents]:
        if p.exists() and (p.is_symlink() or getattr(p.stat(), 'st_file_attributes', 0) & 0x400):
            raise RuntimeError('Reparse point refused: ' + str(p))
    return path

def installed():
    receipt = load(Path(os.environ['ProgramData']) / 'RansomGuard/installation-receipt.json')
    backend = Path(receipt['paths']['python']).parent.parent / 'backend'
    if not backend.is_dir(): raise RuntimeError('Installed backend missing')
    sys.path.insert(0, str(backend))
    return receipt, Path(receipt['runtime'])

def health(base):
    # Scope changes publish a brief running handshake before statistics exist.
    # Wait for real complete telemetry; never substitute zero counters.
    deadline = time.monotonic() + 60
    while True:
        h = load(base / 'observer-ready.json')
        complete = all(k in h for k in ('counter_totals', 'driver_status', 'pending_intake'))
        if complete and h.get('worker_state') == 'running' and time.time() - h.get('observed_at', 0) <= 15:
            return h
        if time.monotonic() >= deadline:
            raise RuntimeError('Collector has no fresh complete statistics after 60 seconds; test refused')
        time.sleep(.5)

def delta(before, after):
    a, b = before['counter_totals'], after['counter_totals']
    keys = ('events_generated', 'events_delivered', 'events_dropped', 'events_flushed')
    result = {k: b[k] - a[k] for k in keys}
    if before.get('pid') != after.get('pid') or any(v < 0 for v in result.values()):
        raise RuntimeError('Collector restarted or counters reset; comparison is invalid')
    return result

def settled(base, seconds=120):
    deadline = time.monotonic() + seconds
    time.sleep(2)
    while True:
        h = health(base)
        if h.get('pending_intake', 1) == 0 and h['driver_status'].get('queue_depth', 1) == 0:
            return h
        if time.monotonic() >= deadline: return h
        time.sleep(1)

def prepare():
    safe_tree(HOME); HOME.mkdir(parents=True, exist_ok=True)
    safe_tree(SCOPE)
    marker = HOME / 'ownership.json'
    if SCOPE.exists():
        if not marker.exists() or load(marker).get('owner') != 'Ransom0TestLab-v1':
            raise RuntimeError('Existing unowned folder refused')
        if {p.name for p in SCOPE.iterdir()} != set(NAMES):
            raise RuntimeError('Unexpected files in test folder; manual review required')
        for p in SCOPE.iterdir(): safe_tree(p)
        return load(marker)
    SCOPE.mkdir()
    for n in NAMES:
        with (SCOPE / n).open('xb') as f: f.write(('Ransom0 harmless baseline ' + n + '\n').encode() * 100)
    value = {'owner': 'Ransom0TestLab-v1', 'folder': str(SCOPE),
             'hashes': {n: digest(SCOPE/n) for n in NAMES}}
    save(marker, value)
    return value

def require_scope(base):
    owned = prepare()
    cfg = load(base/'protection.json')
    if Path(cfg['protected_root']).resolve() != SCOPE.resolve():
        raise RuntimeError('Select ONLY this test folder in Ransom0 settings first: ' + str(SCOPE))
    if any(digest(SCOPE/n) != owned['hashes'][n] for n in NAMES):
        raise RuntimeError('Test baseline changed. Restore and review before another response test.')
    from ransomguard.scope_settings import assert_idle
    assert_idle(base)
    return owned, cfg

def workload(profile, run, count):
    safe_tree(run)
    if profile == 'burst':
        with (run/'writes.txt').open('xb', buffering=0) as f:
            for i in range(count): f.write(('Ransom0 normal text %08d\n' % i).encode())
            os.fsync(f.fileno())
    elif profile == 'mixed':
        for i in range(count):
            p = run / ('normal-%04d.txt' % (i % 64)); q = p.with_suffix('.renamed')
            safe_tree(p); safe_tree(q)
            p.write_text('Normal save and rename %d\n' % i)
            p.rename(q); q.rename(p)
            if i % 100 == 0: time.sleep(.05)
    elif profile == 'process':
        for i in range(count):
            subprocess.run([sys.executable, '-I', '-c', 'pass'], check=True, timeout=10,
                           creationflags=0x08000000 if os.name=='nt' else 0)
    else: raise ValueError('Unknown workload')

def recovery(base):
    owned, cfg = require_scope(base)
    from ransomguard.snapshot_management import manual
    from ransomguard.recovery import Snapshot, build_plan, RecoveryEngine
    creation = manual(base, str(uuid.uuid4()))
    if not creation.get('created'): raise RuntimeError('Snapshot not created: ' + str(creation.get('reason')))
    snap = Snapshot(**creation['snapshot'])
    manifest = [{'relative_path': n, 'expected_sha256': owned['hashes'][n],
                 'expected_size': (SCOPE/n).stat().st_size} for n in NAMES]
    time.sleep(1)
    plan = build_plan(snap, volume_root=cfg['volume_root'], protected_root=str(SCOPE),
                      manifest=manifest, incident_at=datetime.now(timezone.utc))
    # Only this tool's exact twelve known files, never arbitrary protected files.
    for n in NAMES: safe_tree(SCOPE/n); (SCOPE/n).write_text('Harmless test modification\n')
    result = RecoveryEngine().execute(plan, allow_live=True, manual_restore_confirmed=True)
    hashes_ok = all(digest(SCOPE/n) == owned['hashes'][n] for n in NAMES)
    return {'status': 'PASS' if result['verified'] and hashes_ok else 'FAIL',
            'component': 'real VSS file restoration', 'automatic_response_tested': False,
            'hashes_match': hashes_ok, 'result': result, 'snapshot_id': snap.snapshot_id}

def generation(proc):
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)]*4
    values = [w.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(w.HANDLE(int(proc._handle)), *[ctypes.byref(v) for v in values]):
        raise ctypes.WinError(ctypes.get_last_error())
    return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime

def query(base, sql, args=()):
    with closing(sqlite3.connect((base/'observe.sqlite3').resolve().as_uri()+'?mode=ro', uri=True, timeout=2)) as db:
        deadline = time.monotonic()+2
        db.set_progress_handler(lambda: int(time.monotonic()>deadline), 1000)
        return db.execute(sql, args).fetchall()

def kernel_block(base, run):
    """Test the real child-create rule without any destructive VSS operation."""
    import shutil
    source=Path(os.environ['SystemRoot'])/'System32/where.exe'
    probe=run/'vssadmin.exe';shutil.copyfile(source,probe)
    if digest(source)!=digest(probe):raise RuntimeError('WHERE copy hash mismatch')
    start=query(base,"SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'),0)")[0][0]
    denied=False;exit_code=None
    try:
        p=subprocess.run([str(probe),'delete','shadows'],capture_output=True,timeout=10)
        exit_code=p.returncode
    except OSError as e:
        denied=getattr(e,'winerror',None)==5
    until=time.monotonic()+30;records=[]
    while time.monotonic()<until:
        records=query(base,"SELECT payload FROM all_outbox_events WHERE sequence>? AND kind='track_a_command_preempted' AND json_extract(payload,'$.parent_pid')=? ORDER BY sequence LIMIT 10",(start,os.getpid()))
        if records:break
        time.sleep(1)
    evidence=[json.loads(r[0]) for r in records]
    confirmed=denied and any(e.get('process_creation_denied') is True and e.get('rule_id') in range(1001,1009) for e in evidence)
    return {'status':'PASS' if confirmed else 'INCONCLUSIVE','component':'kernel child creation block',
            'process_creation_denied':denied,'matched_events':evidence,'probe_exit_code':exit_code,
            'real_vss_delete_executed':False,'parent_kill_tested':False,'recovery_tested':False,'jev_called_by_test_tool':False}

def response(base, run, track, allow_jev):
    owned, cfg = require_scope(base)
    if track == 'B' and not allow_jev:
        raise RuntimeError('Track B may send test metrics to configured JEV; explicit --allow-jev required')
    installation = load(base/'installation.json')
    if installation.get('evidence_mode') != 'test': raise RuntimeError('Only test-labelled installations supported')
    runtime = load(base/'runtime.json')
    if runtime.get('mode') != 'scoped-live-track-a-b': raise RuntimeError('Automatic A/B response is not enabled; configure test folder and JEV first')
    from ransomguard.snapshot_management import manual
    from ransomguard.protection_setup import refresh
    snap = manual(base, str(uuid.uuid4()))
    if not snap.get('created'): raise RuntimeError('Pre-test snapshot could not be created')
    baseline = refresh(base)
    if not baseline.get('ready'): raise RuntimeError('Verified baseline is not ready')
    import shutil
    if track == 'A':
        # Harmless Windows WHERE copy; never invokes the actual VSS deletion utility.
        source = Path(os.environ['SystemRoot'])/'System32/where.exe'
        shutil.copyfile(source, run/'vssadmin.exe')
        if digest(source) != digest(run/'vssadmin.exe'): raise RuntimeError('Probe binary hash mismatch')
    start = query(base, 'SELECT COALESCE(MAX(sequence),0) FROM events')[0][0]
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child', track, str(run)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=0x08000000)
    deadline = time.monotonic()+100; rows=[]; forced=False
    try:
        gen = generation(proc)
        while time.monotonic()<deadline:
            rows = query(base, 'SELECT incident_id,state,reason FROM live_response_attempts WHERE pid=? AND process_create_time=?', (proc.pid,gen))
            if rows and rows[0][1] in ('RELEASED','REVIEW_REQUIRED','EXEMPTED'): break
            time.sleep(1)
        naturally_exited = proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.terminate(); proc.wait(10); forced=True
    records=[]
    if rows:
        records = [{'kind': k, 'data': json.loads(v)} for k,v in query(base,
            'SELECT kind,payload FROM all_outbox_events WHERE sequence>? AND incident_id=? ORDER BY sequence LIMIT 200', (start, rows[0][0]))]
    kinds = {r['kind'] for r in records}
    restored = all((SCOPE/n).exists() and digest(SCOPE/n)==owned['hashes'][n] for n in NAMES)
    termination = ('process_exit_confirmed' in kinds and 'kernel_termination_request_acknowledged' in kinds
                   and naturally_exited and not forced)
    verified_restore = 'restore_verified' in kinds and restored
    track_confirmed = any(r['data'].get('track')==track for r in records if r['kind']=='detection_recorded')
    jev_confirmed = track!='B' or 'jev_responded' in kinds
    ok = termination and verified_restore and track_confirmed and jev_confirmed and bool(rows) and rows[0][1]=='RELEASED'
    return {'status':'PASS' if ok else 'INCONCLUSIVE', 'track':track, 'pid':proc.pid, 'generation':gen,
            'ledger':rows, 'termination_confirmed':termination, 'restore_confirmed':verified_restore,
            'test_cleanup_terminated_child':forced, 'hashes_match':restored,
            'requested_track_confirmed':track_confirmed, 'jev_response_confirmed':track=='B' and 'jev_responded' in kinds,
            'event_kinds':sorted(kinds), 'network_packet_enforcement_tested':False,
            'note':'No verdict override. Benign/ambiguous JEV or unmet rules are not a blocking pass. Holds are never auto-cleared by this tool.'}

def child(track, run):
    # Delayed stimulus lets the reader bind the real process generation.
    prepare(); time.sleep(3)
    for n in NAMES:
        p=safe_tree(SCOPE/n)
        p.write_bytes(os.urandom(8192))
        if track=='B':
            q=safe_tree(p.with_suffix('.r0test')); p.rename(q); q.rename(p)
        time.sleep(.05)
    if track=='A':
        probe=Path(run)/'vssadmin.exe'
        if digest(probe)!=digest(Path(os.environ['SystemRoot'])/'System32/where.exe'): raise RuntimeError('Not a WHERE copy')
        try: subprocess.run([str(probe),'delete','shadows'],timeout=10,capture_output=True)
        except OSError: pass
    time.sleep(110)

def main():
    if len(sys.argv)>1 and sys.argv[1]=='--child':
        child(sys.argv[2],sys.argv[3]); return 0
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('profile',choices=['prepare','idle','burst','mixed','process','recovery','kernel-block','track-a','track-b'])
    ap.add_argument('--count',type=int,default=None)
    ap.add_argument('--seconds',type=int,default=30)
    ap.add_argument('--allow-jev',action='store_true')
    ap.add_argument('--confirm-test',action='store_true')
    a=ap.parse_args()
    if not a.confirm_test: ap.error('Use --confirm-test only on your approved test VM')
    if os.name!='nt': raise RuntimeError('Windows only')
    if not ctypes.windll.shell32.IsUserAnAdmin(): raise RuntimeError('Run the launcher as administrator')
    safe_tree(HOME); HOME.mkdir(exist_ok=True,parents=True)
    run=HOME/'Runs'/uuid.uuid4().hex; safe_tree(run); run.mkdir(parents=True)
    report={'schema':1,'mode':'test','run_id':run.name,'profile':a.profile,'started':time.time()}
    try:
        if a.profile=='prepare': report.update(status='PASS',prepared=prepare())
        else:
            receipt,base=installed(); before=health(base); report['before']=before['counter_totals']
            if a.profile=='idle':
                if not 5<=a.seconds<=300: raise ValueError('seconds must be 5..300')
                time.sleep(a.seconds)
            elif a.profile in ('burst','mixed','process'):
                cap={'burst':120000,'mixed':12000,'process':300}[a.profile]
                count=a.count if a.count is not None else {'burst':12000,'mixed':1000,'process':50}[a.profile]
                if not 1<=count<=cap: raise ValueError('count must be 1..%d'%cap)
                begin=time.monotonic(); workload(a.profile,run,count)
                report.update(operations=count,workload_seconds=time.monotonic()-begin)
            elif a.profile=='recovery': report.update(recovery(base))
            elif a.profile=='kernel-block': report.update(kernel_block(base,run))
            else: report.update(response(base,run,'A' if a.profile=='track-a' else 'B',a.allow_jev))
            after=settled(base); d=delta(before,after)
            report.update(after=after['counter_totals'],delta=d,queue=after['driver_status'].get('queue_depth'),pending=after.get('pending_intake'))
            if d['events_dropped'] or d['events_flushed']: report['status']='FAIL'
            elif report.get('status') is None:
                report['status']='PASS' if report['queue']==0 and report['pending']==0 else 'INCONCLUSIVE'
                if a.profile!='idle' and d['events_generated']==0: report['status']='INCONCLUSIVE'
        report.setdefault('status','INCONCLUSIVE')
    except Exception as e:
        report.update(status='ERROR',error=type(e).__name__+': '+str(e))
    report['finished']=time.time(); save(run/'report.json',report)
    (run/'report.txt').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8-sig')
    print(json.dumps(report,ensure_ascii=True,indent=2)); print('REPORT: '+str(run/'report.txt'))
    return 0 if report['status']=='PASS' else 2

if __name__=='__main__': sys.exit(main())
