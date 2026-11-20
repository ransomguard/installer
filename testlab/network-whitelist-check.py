"""Real IPv4 HTTPS probes around one unchanged Track A test; no policy writes."""
import concurrent.futures
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import uuid

def evaluate(rounds):
    baseline=[r for r in rounds if r['phase']=='before']
    after=[r for r in rounds if r['phase']=='after']
    valid=lambda r,active: r['before'].get('active') is active and r['after'].get('active') is active and r['before'].get('whitelist')==r['after'].get('whitelist')
    online=lambda rows: any(valid(r,False) and all(p.get('https') for p in r['probes']) for r in rows)
    during=[r for r in rounds if r['phase']=='during' and valid(r,True) and r.get('target_roles_verified') is True]
    if any(r['probes'][1].get('tcp') for r in during):
        return 'FAIL', 'Unlisted target accepted a new TCP connection during isolation'
    if any(r['probes'][0].get('winerror')==10013 for r in during):
        return 'FAIL', 'Allowlisted target was explicitly denied during isolation'
    if not online(baseline) or not online(after):
        return 'INCONCLUSIVE', 'Both targets must be reachable before and after isolation'
    if any(r['probes'][0].get('https') and r['probes'][1].get('winerror')==10013 for r in during):
        return 'PASS', 'Allowlisted HTTPS succeeded and unlisted connection was denied in the same isolation observation'
    return 'INCONCLUSIVE', 'No complete isolation observation with explicit denial; timeouts alone do not prove blocking'

def native_https(host, ip):
    """Use Windows curl's certificate validation; never use --insecure."""
    curl=Path(os.environ['SystemRoot'])/'System32/curl.exe'
    command=[str(curl),'--silent','--show-error','--head','--noproxy','*',
             '--connect-timeout','1','--max-time','3','--resolve',host+':443:'+ip,
             '--output',os.devnull,'--write-out','%{http_code} %{remote_ip}',
             'https://'+host+'/']
    try:
        done=subprocess.run(command,capture_output=True,text=True,timeout=5,creationflags=0x08000000)
        parts=done.stdout.strip().split()
        return {'transport':'Windows curl; certificate validation enabled','exit_code':done.returncode,
                'https':done.returncode==0 and len(parts)==2 and parts[0].isdigit() and 100<=int(parts[0])<=599 and parts[1]==ip,
                'http_result':done.stdout.strip(),'error':done.stderr[:1000]}
    except Exception as e:
        return {'https':False,'error_type':type(e).__name__}

def main():
    share=Path(__file__).parent
    run=Path(os.environ.get('ProgramData','C:/ProgramData'))/'Ransom0TestLab/NetworkChecks'/uuid.uuid4().hex
    run.mkdir(parents=True)
    result={'started':time.time(),'scope':'IPv4 TCP/HTTPS port 443; two destinations only','rounds':[], 'policy_modified':False}
    proc=None
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('Administrator PowerShell required')
        receipt=json.loads(Path('C:/ProgramData/RansomGuard/installation-receipt.json').read_text(encoding='utf-8-sig'))
        sys.path.insert(0,str(Path(receipt['paths']['python']).parent.parent/'backend'))
        from ransomguard.firewall_ipc import FirewallIpcClient
        client=FirewallIpcClient(timeout_ms=1000)
        def state():
            data=client.request('get')
            return {'at':time.time(),'active':data['active'],'whitelist':data['whitelist']}
        initial=state()
        result['initial']=initial
        if initial['active']:raise RuntimeError('Already isolated; no new Track A test started')
        allowed=[x for x in initial['whitelist'] if x['data'].get('domain')=='example.com' and x['data'].get('port') in (0,443)]
        if len(allowed)!=1:raise RuntimeError('Expected existing example.com:443 whitelist entry; settings unchanged')
        # Restrict interpretation to the known two domain rules. Other broad
        # rules require choosing a different control rather than guessing.
        if any(x['type'] not in ('domain','url') or x['data'].get('domain') not in ('example.com','api.typesafe.ai') for x in initial['whitelist']):
            raise RuntimeError('Additional whitelist rules require review before selecting an unlisted control')
        ips=allowed[0]['data'].get('ipv4',[])
        if not isinstance(ips,list) or not ips:raise RuntimeError('Allowlisted IPv4 address unavailable; settings unchanged')
        control=socket.getaddrinfo('www.naver.com',443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        all_allowed={ip for x in initial['whitelist'] for ip in x['data'].get('ipv4',[])}
        if control in all_allowed:raise RuntimeError('Control address overlaps whitelist')
        targets=[('example.com',ips[0]),('www.naver.com',control)]
        result['targets']=targets
        tls=ssl.create_default_context()
        def probe(target):
            host,ip=target
            p={'host':host,'ip':ip,'started':time.time(),'tcp':False,'https':False}
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0)
                    sock.connect((ip,443));p['tcp']=True
                    with tls.wrap_socket(sock,server_hostname=host) as secure:
                        secure.sendall(('HEAD / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n').encode('ascii'))
                        line=secure.recv(512).split(b'\r\n',1)[0].decode('ascii','replace')
                        p['http_status_line']=line
                        p['https']=line.startswith('HTTP/')
            except ssl.SSLCertVerificationError as e:
                p.update(error_type=type(e).__name__,verify_code=e.verify_code,verify_message=e.verify_message)
                p['native_https']=native_https(host,ip)
                p['https']=p['native_https']['https']
            except Exception as e:
                p.update(error_type=type(e).__name__,winerror=getattr(e,'winerror',None),errno=getattr(e,'errno',None))
            p['finished']=time.time()
            return p
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            def check(phase):
                before=state()
                futures=[pool.submit(probe,t) for t in targets]
                probes=[f.result() for f in futures]
                after=state()
                rules=before['whitelist']
                known=all(x['type'] in ('domain','url') and x['data'].get('domain') in ('example.com','api.typesafe.ai') for x in rules)
                addresses={ip for x in rules for ip in x['data'].get('ipv4',[])}
                permitted=any(x['data'].get('domain')=='example.com' and targets[0][1] in x['data'].get('ipv4',[]) and x['data'].get('port') in (0,443) for x in rules)
                result['rounds'].append({'phase':phase,'before':before,'after':after,'probes':probes,'target_roles_verified':known and permitted and control not in addresses})
                return all(p['https'] for p in probes) and before['active'] is False and after['active'] is False
            if not check('before'):raise RuntimeError('Baseline HTTPS failed; no new Track A test started')
            testlab=share/'testlab.py'
            manifest=json.loads((share/'manifest.json').read_text())
            if hashlib.sha256(testlab.read_bytes()).hexdigest()!=manifest['testlab_sha256']:raise RuntimeError('TestLab hash mismatch')
            result['testlab_sha256']=manifest['testlab_sha256']
            print('Baseline OK; starting Track A and observing fresh connections',flush=True)
            with (run/'track-a-console.txt').open('w',encoding='utf8') as log:
                proc=subprocess.Popen([receipt['paths']['python'],'-X','utf8',str(testlab),'track-a','--confirm-test'],stdout=log,stderr=subprocess.STDOUT,creationflags=0x08000000)
                deadline=time.monotonic()+240
                while proc.poll() is None and time.monotonic()<deadline:
                    check('during')
                    time.sleep(.25)
                result['test_exit_code']=proc.poll()
                if proc.poll() is None:
                    raise RuntimeError('Observation timed out; test process left to finish safely; isolation was not cleared')
            for _ in range(2):
                check('after');time.sleep(.5)
        result['network_status'],result['reason']=evaluate(result['rounds'])
        if result['test_exit_code']!=0:
            result['overall_status']='INCONCLUSIVE'
        else:result['overall_status']=result['network_status']
    except Exception as e:
        result.update(overall_status='INCONCLUSIVE',error=str(e))
    finally:
        result['finished']=time.time()
        result['test_process_still_running']=proc is not None and proc.poll() is None
        dest=run/'network-report.json'
        dest.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
        (run.parent/'latest-result.json').write_text(json.dumps({'report':str(dest),'status':result['overall_status']}),encoding='utf8')
        print(result['overall_status']+': '+str(dest),flush=True)
    return 0 if result['overall_status']=='PASS' else 2

if __name__=='__main__':sys.exit(main())
