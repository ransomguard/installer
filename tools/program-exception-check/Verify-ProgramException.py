"""Bounded real Track A control/exception/removal comparison on owned test files."""
import json,os,sys,time,uuid,shutil,subprocess,hashlib
from pathlib import Path
from datetime import datetime,timezone
HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
import testlab as t
report={'started':time.time(),'result':'RUNNING','phases':[],'ui_button_clicked':False,'registration_interface':'same program_allowlist backend as dashboard'}
dest=HERE/'ProgramException-Result.json'
def save():
 tmp=dest.with_suffix('.tmp');tmp.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');os.replace(tmp,dest)
def expect(ok,msg):
 if not ok:raise RuntimeError(msg)
def policy(action,request=None):
 p=subprocess.run([receipt['paths']['python'],'-X','utf8','-m','ransomguard.program_allowlist','--runtime',str(base),action],input=json.dumps(request or {}),text=True,encoding='utf8',capture_output=True,timeout=30,cwd=backend,creationflags=0x08000000)
 expect(p.returncode==0,'Program policy command failed: '+p.stdout[-1000:]);return json.loads(p.stdout.strip().splitlines()[-1])['entries']
def rows(sql,args=()):return t.query(base,sql,args)
def phase(name,exempt):
 from ransomguard.snapshot_management import manual
 from ransomguard.protection_setup import refresh
 from ransomguard.recovery import Snapshot,build_plan,RecoveryEngine
 t.require_scope(base);t.require_live_worker(base,'A')
 before=t.settled(base);expect(before['pending_intake']==0 and before['driver_status']['queue_depth']==0,'Backlog not drained')
 expect(client.request('get')['active'] is False,'Already isolated; test refused')
 snap=manual(base,str(uuid.uuid4()));expect(snap.get('created'),'Snapshot preparation failed')
 expect(refresh(base).get('ready'),'Baseline not ready')
 manifest=[{'relative_path':n,'expected_sha256':owned['hashes'][n],'expected_size':(t.SCOPE/n).stat().st_size} for n in t.NAMES]
 plan=build_plan(Snapshot(**snap['snapshot']),volume_root=cfg['volume_root'],protected_root=str(t.SCOPE),manifest=manifest,incident_at=datetime.now(timezone.utc))
 start=rows("SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'),0)")[0][0]
 record={'name':name,'registered':exempt,'before':before['counter_totals'],'start_sequence':start};report['phases'].append(record);save()
 proc=subprocess.Popen([str(probe),str(run)],creationflags=0x08000000)
 forced=False
 try:
  gen=t.generation(proc);record.update(pid=proc.pid,generation=gen)
  deadline=time.monotonic()+100;attempt=[]
  while time.monotonic()<deadline:
   attempt=rows('SELECT incident_id,state,reason FROM live_response_attempts WHERE pid=? AND process_create_time=?',(proc.pid,gen))
   if attempt and attempt[0][1] in ('RELEASED','EXEMPTED','REVIEW_REQUIRED'):break
   time.sleep(1)
  record['ledger']=attempt;record['alive_at_decision']=proc.poll() is None
  if attempt and attempt[0][1]=='EXEMPTED':time.sleep(5)
  record['alive_after_grace']=proc.poll() is None
  events=rows('SELECT kind,payload FROM all_outbox_events WHERE sequence>? AND incident_id=? ORDER BY sequence LIMIT 200',(start,attempt[0][0])) if attempt else []
  record['events']=[{'kind':k,'data':json.loads(v)} for k,v in events];kinds={k for k,v in events}
  direct=rows("SELECT payload FROM all_outbox_events WHERE sequence>? AND kind='track_a_command_preempted' AND json_extract(payload,'$.parent_pid')=? ORDER BY sequence LIMIT 10",(start,proc.pid))
  record['kernel_child_block']=[json.loads(x[0]) for x in direct]
  record['firewall_active_after_decision']=client.request('get')['active']
  record['hashes_before_cleanup']=all(t.digest(t.SCOPE/n)==owned['hashes'][n] for n in t.NAMES)
  actions={'host_outbound_block_requested','termination_requested','kernel_termination_request_acknowledged','restore_started','restore_verified'}
  if exempt:
   rule=next((e['data'].get('program_exception') for e in record['events'] if e['kind']=='automatic_response_exempted'),None)
   record['exception_rule']=rule
   ok=bool(attempt and attempt[0][1]=='EXEMPTED' and rule and rule['id']==added_id and rule['sha256']==t.digest(probe) and record['alive_after_grace'] and not actions.intersection(kinds) and record['firewall_active_after_decision'] is False and not record['hashes_before_cleanup'] and 'detection_recorded' in kinds and any(x.get('process_creation_denied') for x in record['kernel_child_block']))
  else:
   ok=bool(attempt and attempt[0][1]=='RELEASED' and {'process_exit_confirmed','kernel_termination_request_acknowledged','restore_verified'}<=kinds and not record['alive_after_grace'] and record['hashes_before_cleanup'])
  record['behavior_pass']=ok;save()
 finally:
  if proc.poll() is None:proc.terminate();proc.wait(10);forced=True
  record['test_cleanup_terminated_probe']=forced
  # Restore only known test files from the pre-test snapshot after all jobs stop.
  from ransomguard.scope_settings import assert_idle
  try:
   assert_idle(base)
   if any(t.digest(t.SCOPE/n)!=owned['hashes'][n] for n in t.NAMES):
    record['manual_test_cleanup_restore']=RecoveryEngine().execute(plan,allow_live=True,manual_restore_confirmed=True)
   record['cleanup_hashes_match']=all(t.digest(t.SCOPE/n)==owned['hashes'][n] for n in t.NAMES)
  except Exception as e:record['cleanup_error']=str(e)
  save()
 after=t.settled(base);record['delta']=t.delta(before,after);record['pending']=after['pending_intake'];record['queue']=after['driver_status']['queue_depth']
 record['result']='PASS' if record['behavior_pass'] and record.get('cleanup_hashes_match') and record['delta']['events_dropped']==0 and record['delta']['events_flushed']==0 and record['pending']==0 and record['queue']==0 else 'FAIL'
 save();print(name+': '+record['result'],flush=True);expect(record['result']=='PASS',name+' did not pass; later phases not started')
added_id=None;maintenance=None;owner=uuid.uuid4().hex
try:
 save();receipt,base=t.installed();backend=str(Path(receipt['paths']['python']).parent.parent/'backend')
 from ransomguard.firewall_ipc import FirewallIpcClient
 client=FirewallIpcClient(timeout_ms=1500)
 owned,cfg=t.require_scope(base);t.require_live_worker(base,'A')
 report['before_health']=t.health(base)
 expect(report['before_health'].get('internal_collection',{}).get('collect') is False,'Expected own DB OFF')
 run=t.HOME/'ProgramChecks'/owner;t.safe_tree(run);run.mkdir(parents=True)
 probe=run/'ProgramExceptionProbe.exe'
 expected=json.loads((HERE/'probe-manifest.json').read_text())
 expect(t.digest(HERE/'ProgramExceptionProbe.exe')==expected['sha256'],'Probe checksum mismatch')
 shutil.copyfile(HERE/'ProgramExceptionProbe.exe',probe)
 source=Path(os.environ['SystemRoot'])/'System32/where.exe';shutil.copyfile(source,run/'vssadmin.exe');expect(t.digest(source)==t.digest(run/'vssadmin.exe'),'Harmless WHERE hash mismatch')
 report.update(run=str(run),probe=str(probe),probe_sha256=t.digest(probe),policy_before=policy('program-list'))
 maintenance=base/'supervisor-maintenance.json';expect(not maintenance.exists(),'Existing maintenance task')
 maintenance.write_text(json.dumps({'owner':owner,'created_at':time.time(),'until':time.time()+1200,'reason':'Bounded program response exception validation'}),encoding='utf8')
 print('CONTROL: unregistered dedicated probe',flush=True);phase('unregistered',False)
 registered=policy('program-add',{'path':str(probe)});added=next(x for x in registered if os.path.normcase(x['path'])==os.path.normcase(str(probe)));added_id=added['id'];report['registered_entry']=added;save()
 print('EXCEPTION: same executable registered by exact path and SHA256',flush=True);phase('registered',True)
 policy('program-remove',{'id':added_id});added_id=None
 print('REMOVAL: exception removed; normal response should return',flush=True);phase('removed',False)
 report['result']='PASS'
except Exception as e:report['result']='ERROR';report['error']=str(e)
finally:
 if added_id:
  try:policy('program-remove',{'id':added_id});report['temporary_exception_removed']=True
  except Exception as e:report['policy_cleanup_error']=str(e);report['result']='ERROR'
 if 'base' in globals():
  try:
   report['policy_after']=policy('program-list')
   report['policy_restored']=report.get('policy_before')==report['policy_after']
   if not report['policy_restored']:report['result']='ERROR'
   report['after_health']=t.health(base)
  except Exception as e:report['final_check_error']=str(e);report['result']='ERROR'
 if maintenance and maintenance.exists() and json.loads(maintenance.read_text()).get('owner')==owner:maintenance.unlink()
 report['finished']=time.time();save();print('COMPLETE: '+report['result']+'; ProgramException-Result.json',flush=True)
